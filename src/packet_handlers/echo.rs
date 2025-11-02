use std::io::Read;

use anyhow::Result;

pub struct EchoHandler {}

impl EchoHandler {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle a raw packet of the echo service.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet<R: Read>(
        &mut self,
        packet: &mut R,
        _options: (),
    ) -> Result<Option<Vec<u8>>> {
        log::trace!("received echo packet...");
        let mut buffer = [0u8; 65535];
        let mut out = Vec::new();

        loop {
            let read_amount = packet.read(&mut buffer)?;
            if read_amount == 0 {
                break;
            }
            out.extend_from_slice(&buffer[..read_amount])
        }
        Ok(Some(out))
    }
}
