use anyhow::{Result, anyhow, bail};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{Packet, ipv4};

use crate::constants::IPV4_HEADER_LEN;
use crate::packet_handlers::ipv4_test1::Ipv4Test1Handler;
use crate::packet_handlers::tcp::{TcpHandler, TcpHandlerOptions};

pub struct Ipv4Handler {
    tcp_handler: TcpHandler,
    test1_handler: Ipv4Test1Handler,
}

impl Ipv4Handler {
    pub fn new() -> Self {
        Self {
            tcp_handler: TcpHandler::new(),
            test1_handler: Ipv4Test1Handler::new(),
        }
    }

    /// Handle a raw IPv4 packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        log::trace!("received ipv4 packet...");

        let Some(inbound_ipv4_packet) = Ipv4Packet::new(packet) else {
            bail!("cannot create ipv4 packet...")
        };

        let res = match inbound_ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let options = TcpHandlerOptions {
                    src_ip: inbound_ipv4_packet.get_source(),
                    dst_ip: inbound_ipv4_packet.get_destination(),
                };
                self.tcp_handler
                    .handle_packet(inbound_ipv4_packet.payload(), &options)?
            }
            IpNextHeaderProtocols::Test1 => self
                .test1_handler
                .handle_packet(inbound_ipv4_packet.payload(), ())?,
            p => {
                log::trace!("unhandled proto {p}...");
                return Ok(None);
            }
        };

        match res {
            None => Ok(None),
            Some(payload) => {
                let packet_len: usize = IPV4_HEADER_LEN + payload.len();

                let mut data = vec![0u8; packet_len];

                let mut outbound_ipv4_packet =
                    MutableIpv4Packet::new(&mut data).ok_or(anyhow!("cannot build ipv4 packet"))?;

                outbound_ipv4_packet.set_source(inbound_ipv4_packet.get_destination());
                outbound_ipv4_packet.set_destination(inbound_ipv4_packet.get_source());
                outbound_ipv4_packet.set_version(inbound_ipv4_packet.get_version());
                outbound_ipv4_packet
                    .set_next_level_protocol(inbound_ipv4_packet.get_next_level_protocol());
                outbound_ipv4_packet.set_header_length(5); // minimum packet size 20 bytes => 5 increments of 4 bytes
                outbound_ipv4_packet.set_total_length(packet_len as u16);
                outbound_ipv4_packet.set_ttl(inbound_ipv4_packet.get_ttl());
                outbound_ipv4_packet.set_flags(Ipv4Flags::DontFragment);

                outbound_ipv4_packet.set_payload(&payload);
                outbound_ipv4_packet
                    .set_checksum(ipv4::checksum(&outbound_ipv4_packet.to_immutable()));

                Ok(Some(data))
            }
        }
    }
}
