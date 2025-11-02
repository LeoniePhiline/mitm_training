// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use std::{collections::HashMap, io::Read};

use color_eyre::Result;
use rustls::ServerConnection;

use crate::{models::ConnectionId, packet_handlers::http::HttpHandler};

pub struct TlsHandlerOptions {
    pub conn_id: ConnectionId,
}

pub struct TlsHandler {
    http: HttpHandler,
    active_connections: HashMap<ConnectionId, ServerConnection>,
}

impl TlsHandler {
    pub fn new() -> Self {
        Self {
            http: HttpHandler::new(),
            active_connections: HashMap::new(),
        }
    }

    /// Handle new data for incoming tls packet.
    ///
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error    
    pub fn handle_packet<R: Read>(
        &mut self,
        packet: &mut R,
        options: &TlsHandlerOptions,
    ) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 5.1 - Optional
        // Implement the handling of a TLS packet. This should call the HTTP
        // handler you have already developed once the handshake is complete
        // and the data is decrypted.
        // You will have to generate a valid self-signed TLS certificate for the
        // requested domain. We recommend using `rustls` for the TLS
        // implementation. You can start by hard-coding the certificates, but
        // they can be generated on the fly for the requested domain name.
        // Once correctly implemented, you should pass test case #6 and test
        // case #7 for https if you have correctly implemented the HttpHandler.

        if !self.should_intercept() {
            return Ok(None);
        }

        Ok(None)
    }

    fn should_intercept(&self) -> bool {
        // TODO: implement your custom interception logic here. You may pass
        // additional parameters to this function.
        true
    }
}
