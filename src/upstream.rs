use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::{Result, anyhow};
use http::header::{CONTENT_LENGTH, HOST};
use http::{HeaderName, HeaderValue, Response, Uri};
use ureq::tls::TlsConfig;
use ureq::unversioned::resolver::Resolver;
use ureq::unversioned::transport::DefaultConnector;
use ureq::{Agent, Body};

fn craft_upstream_uri(
    is_encrypted_layer: bool,
    authority: &str,
    path_and_query: Option<&str>,
) -> Result<String> {
    let scheme = if is_encrypted_layer { "https" } else { "http" };

    let mut builder = Uri::builder().scheme(scheme).authority(authority);
    if let Some(path_and_query) = path_and_query {
        builder = builder.path_and_query(path_and_query);
    }

    let uri = builder.build()?;
    Ok(uri.to_string())
}

#[derive(Debug)]
pub struct CustomResolver {
    mapping: HashMap<String, Ipv4Addr>,
}

impl CustomResolver {
    pub fn new(mapping: HashMap<String, Ipv4Addr>) -> Self {
        Self { mapping }
    }
}

impl Resolver for CustomResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> std::result::Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut res = self.empty();

        if let Some(host) = uri.host() {
            if let Some(ip) = self.mapping.get(host) {
                let port = match uri.scheme() {
                    Some(s) if s == "http" => 80,
                    Some(s) if s == "https" => 443,
                    _ => 443,
                };
                log::trace!("static dns lookup {host} => {ip}");
                res.push(SocketAddr::V4(SocketAddrV4::new(ip.to_owned(), port)));
            }
        }

        Ok(res)
    }
}

pub struct UpstreamsManager {
    agent: Agent,
}

impl UpstreamsManager {
    pub fn new(static_domains: HashMap<String, Ipv4Addr>) -> Self {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(
                TlsConfig::builder()
                    .use_sni(true)
                    .disable_verification(true)
                    .build(),
            )
            .build();

        let agent = Agent::with_parts(
            config,
            DefaultConnector::new(),
            CustomResolver::new(static_domains.clone()),
        );

        Self { agent }
    }

    pub fn get(
        &self,
        is_encrypted_layer: bool,
        path_and_query: Option<&str>,
        headers: HashMap<HeaderName, HeaderValue>,
        request_body: &[u8],
    ) -> Result<Response<Body>> {
        let host_header_value = headers
            .get(&HOST)
            .ok_or(anyhow!("no host header provided..."))?;
        let uri = craft_upstream_uri(
            is_encrypted_layer,
            host_header_value.to_str()?,
            path_and_query,
        )?;

        let mut req = self.agent.get(uri).force_send_body();
        let req_headers = req
            .headers_mut()
            .ok_or(anyhow!("cannot get mutable reference on headers"))?;

        req_headers.extend(headers);
        req_headers.remove(CONTENT_LENGTH);

        let response = req.version(http::Version::HTTP_11).send(request_body)?;

        log::debug!("upstream status code: {}", response.status());
        Ok(response)
    }
}
