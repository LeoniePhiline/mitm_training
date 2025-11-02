use color_eyre::{
    eyre::{Ok, OptionExt},
    Result,
};
use pnet::{
    packet::{
        ethernet::{EtherTypes, Ethernet, EthernetPacket, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};
use tracing::{debug, warn};

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
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], options: ()) -> Result<Option<Vec<u8>>> {
        // # Exercise 1.1
        //
        // Implement the handling of an Ethernet packet. This should call
        // another handler's `.handle_packet()` function depending on the
        // payload type.
        // Once you have implemented the logic for handling any Ethernet packet,
        // move on to ArpHandler to perform the ARP spoofing.

        let Some(incoming_packet) = EthernetPacket::new(packet) else {
            warn!("Invalid ethernet packet: {packet:02X?}");
            return Ok(None);
        };

        if !self.should_intercept(&incoming_packet) {
            return Ok(None);
        }

        let ether_type = incoming_packet.get_ethertype();

        debug!(
            "Incoming {ether_type} packet: {incoming_packet:#?} ({:02X?})",
            incoming_packet.packet()
        );

        let Some(payload) = match ether_type {
            EtherTypes::Arp => self.arp.handle_packet(incoming_packet.payload(), options),
            EtherTypes::Ipv4 => self.ipv4.handle_packet(incoming_packet.payload(), options),
            _ => unreachable!(), // Not intercepted.
        }?
        else {
            return Ok(None);
        };

        let params = Ethernet {
            // Sending an Ethernet reply, reversing direction.
            ethertype: incoming_packet.get_ethertype(),
            destination: incoming_packet.get_source(),
            source: self.own_mac_address,

            // Spoof payload.
            payload,
        };
        let mut packet = vec![0u8; EthernetPacket::packet_size(&params)];
        let mut outgoing_packet =
            MutableEthernetPacket::new(&mut packet).ok_or_eyre("cannot build ethernet packet")?;
        outgoing_packet.populate(&params);

        debug!(
            "Outgoing {ether_type} packet: {outgoing_packet:#?} ({:02X?})",
            outgoing_packet.packet()
        );

        Ok(Some(packet))
    }

    fn should_intercept(&self, incoming_packet: &EthernetPacket<'_>) -> bool {
        matches!(
            incoming_packet.get_ethertype(),
            EtherTypes::Arp | EtherTypes::Ipv4
        )
    }
}
