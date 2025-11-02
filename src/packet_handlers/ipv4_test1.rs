use anyhow::Result;

pub struct Ipv4Test1Handler {}

impl Ipv4Test1Handler {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle a raw packet of IPv4 Test1.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        log::trace!("received TEST1 packet...");
        Ok(Some(packet.to_vec()))
    }
}
