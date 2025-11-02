use anyhow::{Ok, Result, anyhow, bail};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use crate::constants::ETHERNET_HEADER_SIZE;
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
        log::trace!("received ETHERNET packet...");
        let Some(inbound_ethernet_packet) = EthernetPacket::new(packet) else {
            bail!("cannot create ethernet packet...");
        };

        if !self.should_intercept(&inbound_ethernet_packet.get_destination()) {
            return Ok(None);
        }

        let res = match inbound_ethernet_packet.get_ethertype() {
            EtherTypes::Arp => self
                .arp
                .handle_packet(inbound_ethernet_packet.payload(), ())?,
            EtherTypes::Ipv4 => self
                .ipv4
                .handle_packet(inbound_ethernet_packet.payload(), ())?,
            e => {
                log::trace!("unhandled ethertype {e}...");
                return Ok(None);
            }
        };

        match res {
            None => Ok(None),
            Some(payload) => {
                let mut data = vec![0u8; ETHERNET_HEADER_SIZE + payload.len()];

                // Swap MAC addresses
                let mut outbound_ethernet_packet = MutableEthernetPacket::new(&mut data)
                    .ok_or(anyhow!("cannot build ethernet packet"))?;

                outbound_ethernet_packet.set_destination(inbound_ethernet_packet.get_source());
                outbound_ethernet_packet.set_source(self.own_mac_address);
                outbound_ethernet_packet.set_ethertype(inbound_ethernet_packet.get_ethertype());
                outbound_ethernet_packet.set_payload(&payload);

                Ok(Some(data))
            }
        }
    }

    fn should_intercept(&self, destination_mac_addr: &MacAddr) -> bool {
        [self.own_mac_address, MacAddr::broadcast(), MacAddr::zero()].contains(destination_mac_addr)
    }
}
