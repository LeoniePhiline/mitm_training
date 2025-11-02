use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

use anyhow::{Result, bail};
use rustls::{ServerConfig, ServerConnection};

use crate::cert_store::ServerCertsStore;
use crate::models::ConnectionId;
use crate::packet_handlers::http::{HttpHandler, HttpHandlerOptions};

pub struct TlsHandlerOptions {
    pub conn_id: ConnectionId,
}

fn make_server_connection(maximum_cached_certs: usize) -> Result<ServerConnection> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ServerCertsStore::new(maximum_cached_certs)?));

    config.alpn_protocols = vec!["http/1.1".as_bytes().to_vec()];

    Ok(ServerConnection::new(Arc::new(config))?)
}

pub struct TlsHandler {
    http: HttpHandler,
    active_connections: HashMap<ConnectionId, ServerConnection>,
    maximum_cached_certs: usize,
}

impl TlsHandler {
    pub fn new() -> Self {
        Self {
            http: HttpHandler::new(),
            active_connections: HashMap::new(),
            maximum_cached_certs: 64,
        }
    }

    /// Handle new data for incoming tls packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error    
    pub fn handle_packet<R: Read>(
        &mut self,
        packet: &mut R,
        options: &TlsHandlerOptions,
    ) -> Result<Option<Vec<u8>>> {
        log::trace!("received tls packet...");

        let conn = match self.active_connections.entry(options.conn_id.clone()) {
            Entry::Occupied(entry) => {
                log::debug!("found existing tls connection");
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                log::debug!("must create tls connection");
                let conn = make_server_connection(self.maximum_cached_certs)?;
                entry.insert(conn)
            }
        };

        match conn.read_tls(packet) {
            Ok(0) => Ok(None),
            Ok(_) => {
                match conn.process_new_packets() {
                    Ok(io_state) => {
                        if !conn.is_handshaking() && io_state.plaintext_bytes_to_read() > 0 {
                            let res = match conn.alpn_protocol() {
                                Some(b"http/1.1") | None => self.http.handle_packet(
                                    &mut conn.reader(),
                                    &HttpHandlerOptions {
                                        is_underlying_layer_encrypted: true,
                                        conn_id: options.conn_id.clone(),
                                    },
                                )?,
                                p => bail!("alpn protocol not implemented: {p:?}"),
                            };

                            let Some(res) = res else { return Ok(None) };

                            conn.writer().write_all(&res)?;
                        }

                        if conn.wants_write() {
                            let mut write_back = Vec::new();
                            conn.write_tls(&mut write_back)?;
                            return Ok(Some(write_back));
                        }
                    }
                    Err(err) => {
                        bail!("TLS error: {err:?}");
                    }
                }

                Ok(None)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => bail!(e),
        }
    }
}
