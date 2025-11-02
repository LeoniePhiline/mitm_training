use std::io::Read;

use color_eyre::Result;

pub struct EchoHandler {}

impl EchoHandler {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle a raw packet of the echo service.
    ///
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet<R: Read>(
        &mut self,
        packet: &mut R,
        _options: (),
    ) -> Result<Option<Vec<u8>>> {
        // # Exercise 3.4
        //
        // Implement the handling of a packet for the Echo service.
        // This service should echo back any received packet.

        if !self.should_intercept() {
            return Ok(None);
        }

        let mut buffer = Vec::new();
        packet.read_to_end(&mut buffer)?;

        Ok(Some(buffer))
    }

    fn should_intercept(&self) -> bool {
        true
    }
}
