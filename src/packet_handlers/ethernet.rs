use color_eyre::{eyre::Ok, Result};
use pnet::{
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        Packet,
    },
    util::MacAddr,
};
use tracing::{trace, warn};

use crate::packet_handlers::arp::ArpHandler;
use crate::packet_handlers::ipv4::Ipv4Handler;

pub struct EthernetHandler {
    arp: ArpHandler,
    ipv4: Ipv4Handler,
    #[expect(dead_code)]
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
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], options: ()) -> Result<Option<Vec<u8>>> {
        if !self.should_intercept() {
            return Ok(None);
        }

        // # Exercise 1.1
        //
        // Implement the handling of an Ethernet packet. This should call
        // another handler's `.handle_packet()` function depending on the
        // payload type.
        // Once you have implemented the logic for handling any Ethernet packet,
        // move on to ArpHandler to perform the ARP spoofing.

        let Some(eth_packet) = EthernetPacket::new(packet) else {
            warn!("Invalid ethernet packet: {packet:02X?}");
            return Ok(None);
        };

        let ether_type = eth_packet.get_ethertype();

        trace!("{ether_type} {:02X?}", packet);

        match ether_type {
            EtherTypes::Arp => self.arp.handle_packet(eth_packet.payload(), options),
            EtherTypes::Ipv4 => self.ipv4.handle_packet(eth_packet.payload(), options),
            ether_type => {
                trace!("Other ethernet frame type: {ether_type:?}");
                Ok(None)
            }
        }
    }

    fn should_intercept(&self) -> bool {
        // TODO: implement your custom interception logic here. You may pass
        // additional parameters to this function.
        true
    }
}
