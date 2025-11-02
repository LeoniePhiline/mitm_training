use color_eyre::Result;

pub struct Ipv4Test1Handler {}

impl Ipv4Test1Handler {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle a raw packet of IPv4 Test1.
    ///
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // # Exercise 2.2
        //
        // Implement the handling of an IPv4 Test1 packet.
        // This service should echo back the received packet.
        // Once correctly implemented, you should pass test case #2.

        if !self.should_intercept() {
            return Ok(None);
        }

        // Echo the payload.
        Ok(Some(packet.to_vec()))
    }

    fn should_intercept(&self) -> bool {
        true
    }
}
