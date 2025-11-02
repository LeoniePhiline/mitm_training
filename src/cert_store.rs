use anyhow::{Result, anyhow};
use lru::LruCache;
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::PrivateKeyDer;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, SigningKey},
};
use rustls_pki_types::pem::PemObject;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct ServerCertsStore {
    generated_certs: RwLock<LruCache<String, Arc<CertifiedKey>>>,
    key_pair: KeyPair,
    signing_key: Arc<dyn SigningKey>,
}

impl ServerCertsStore {
    pub fn new(maximum_cached_certs: usize) -> Result<Self> {
        let key_pair = KeyPair::generate()?;
        let private_key_der = PrivateKeyDer::from_pem_slice(key_pair.serialize_pem().as_bytes())?;

        let signing_key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(private_key_der)?;

        Ok(Self {
            generated_certs: RwLock::new(LruCache::new(
                NonZeroUsize::new(maximum_cached_certs)
                    .ok_or(anyhow!("cannot create cache with 0 elements"))?,
            )),
            key_pair,
            signing_key,
        })
    }

    pub fn generate_cert_for_sni(&self, server_name: &str) -> Result<rcgen::Certificate> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, server_name);
        params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from(server_name)?)];

        let certificate = params.self_signed(&self.key_pair)?;

        Ok(certificate)
    }
}

impl ResolvesServerCert for ServerCertsStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            let mut rw_generated_certs = self.generated_certs.write().ok()?;

            let generate_cert = || -> Result<Arc<CertifiedKey>> {
                log::debug!("must generate new certificate for {server_name}");

                let cert = self.generate_cert_for_sni(server_name)?;

                let cert_key =
                    CertifiedKey::new(vec![cert.der().to_owned()], self.signing_key.clone());

                Ok(Arc::new(cert_key))
            };

            let res = match rw_generated_certs
                .try_get_or_insert(server_name.to_string(), generate_cert)
            {
                Ok(cert) => Some(cert.clone()),
                Err(e) => {
                    log::error!("got error while inserting certificate {e}");
                    None
                }
            };

            return res;
        }

        log::error!("no server name provided in ClientHello...");
        None
    }
}
