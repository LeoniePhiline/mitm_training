// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use std::{collections::HashMap, fmt::Write, io::Read};

use color_eyre::Result;
use http::{
    header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH},
    response::Parts,
    HeaderMap, HeaderValue,
};

use crate::models::ConnectionId;

fn format_response(mut head: Parts, mut body: Vec<u8>) -> Result<(Vec<u8>, usize)> {
    let mut formatted = String::new();
    write!(
        &mut formatted,
        "HTTP/1.1 {} {}\r\n",
        head.status.as_u16(),
        head.status.canonical_reason().unwrap_or("")
    )?;

    format_headers(&mut head.headers, body.len(), &mut formatted)?;

    formatted.push_str("\r\n");

    let mut result = formatted.into_bytes();

    result.append(&mut body);

    let length = result.len();

    Ok((result, length))
}

fn format_headers(headers: &mut HeaderMap, body_len: usize, output: &mut String) -> Result<()> {
    headers.insert(CONNECTION, HeaderValue::from_static("Close"));
    headers.remove(CONTENT_ENCODING);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(body_len));

    for (name, value) in headers.iter() {
        write!(output, "{}: {}\r\n", name.as_str(), value.to_str()?)?;
    }
    Ok(())
}

pub struct HttpHandlerOptions<'a> {
    pub is_underlying_layer_encrypted: bool,
    pub connection_id: &'a ConnectionId,
}

pub struct HttpHandler {
    active_connections_data: HashMap<ConnectionId, Vec<u8>>,
}

impl HttpHandler {
    pub fn new() -> Self {
        Self {
            active_connections_data: HashMap::default(),
        }
    }

    /// Handle new data for incoming http requests.
    ///
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error    
    pub fn handle_packet<R: Read>(
        &mut self,
        packet: &mut R,
        options: &HttpHandlerOptions<'_>,
    ) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 4.1
        //
        // Implement the handling of an HTTP request. This will be the last
        // handler of this training.
        //
        // The first part of this exercise is to forward the incoming request
        // to the legitimate server.
        //
        // For this, we recommend using `httparse` and `ureq`. You can also make use
        // of the provided `crate::upstream::UpstreamsManager` to handle the call
        // to the legitimate server with `ureq`. This struct includes a custom
        // resolver that will help you handle the domain requested by the
        // client.
        //
        // Note: you are now given a reader instead of the raw packet data.
        // Once correctly implemented, you should pass test case #5.

        // TODO: Exercice 4.2
        // The goal of this exercise is to embed a malicous payload in the web
        // page returned to the victim. The payload will be in the form of an
        // embedded `<script>` section.
        //
        // Send the victim the expected web page, but with a malicious payload
        // included in the form of an embedded `<script>` section.
        //
        // You will need to parse and send an HTTP request.
        // Once correctly implemented, you should pass test case #7 for http.

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
