// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

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
        // TODO: Exercise 3.4
        // Implement the handling of a packet for the Echo service.
        // This service should echo back any received packet.
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
