// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use anyhow::Result;
use pnet::util::MacAddr;

pub struct ArpHandler {
    own_mac_address: MacAddr,
}

impl ArpHandler {
    pub fn new(own_mac_address: MacAddr) -> Self {
        Self { own_mac_address }
    }

    /// Handle a raw ARP packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 1.2
        // Implement the handling of an ARP packet. This function should perform
        // the ARP spoofing by sending valid ARP replies to the victim host.
        // Once correctly implemented, you should pass test cases #0 and #1.

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
