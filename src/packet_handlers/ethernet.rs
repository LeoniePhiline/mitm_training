// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use color_eyre::{eyre::Ok, Result};
use pnet::util::MacAddr;

use crate::packet_handlers::arp::ArpHandler;
use crate::packet_handlers::ipv4::Ipv4Handler;

pub struct EthernetHandler {
    arp: ArpHandler,
    ipv4: Ipv4Handler,
    own_mac_address: MacAddr,
}

impl EthernetHandler {
    pub fn new(own_mac_address: MacAddr) -> Self {
        Self {
            arp: ArpHandler::new(own_mac_address),
            ipv4: Ipv4Handler::new(),
            own_mac_address,
        }
    }

    /// Handle a raw ethernet packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        if !self.should_intercept() {
            return Ok(None);
        }

        // TODO: Exercise 1.1
        // Implement the handling of an Ethernet packet. This should call
        // another handler's `.handle_packet()` function depending on the
        // payload type.
        // Once you have implemented the logic for handling any Ethernet packet,
        // move on to ArpHandler to perform the ARP spoofing.

        Ok(None)
    }

    fn should_intercept(&self) -> bool {
        // TODO: implement your custom interception logic here. You may pass
        // additional parameters to this function.
        true
    }
}
