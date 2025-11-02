use color_eyre::{
    eyre::{bail, Context, OptionExt},
    Result,
};
use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{checksum, Ipv4, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    Packet,
};
use tracing::{debug, info, trace};

use crate::{
    constants::{IPV4_HEADER_LEN, SERVER_IP},
    packet_handlers::{ipv4_test1::Ipv4Test1Handler, tcp::TcpHandler},
};

pub struct Ipv4Handler {
    #[expect(unused)]
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
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], options: ()) -> Result<Option<Vec<u8>>> {
        // # Exercise 2.1
        //
        // Implement the handling of an IPv4 packet. This should call another
        // handler's `.handle_packet()` function depending on the payload type.
        // Once you have implemented the logic for handling any IPv4 packet,
        // move on to `IPv4TestHandler` to implement the echo service.

        let Some(incoming_packet) = Ipv4Packet::new(packet) else {
            bail!("could not build IPv4 packet from {packet:02X?}")
        };

        trace!(?incoming_packet, "Incoming IPv4 packet.");

        if !self.should_intercept(&incoming_packet) {
            return Ok(None);
        }

        debug!(?incoming_packet, "Handling IPv4 packet.");

        let Some(payload) = match incoming_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Test1 => self
                .test1_handler
                .handle_packet(incoming_packet.payload(), options),
            IpNextHeaderProtocol(_) => Ok(None),
        }?
        else {
            return Ok(None);
        };

        let mut params = Ipv4 {
            // Fill metadata from incoming packet.
            version: incoming_packet.get_version(),
            dscp: incoming_packet.get_dscp(),
            ecn: incoming_packet.get_ecn(),
            next_level_protocol: incoming_packet.get_next_level_protocol(),

            // Sending an Ipv4 response, reversing direction.
            source: incoming_packet.get_destination(),
            destination: incoming_packet.get_source(),

            // IPv4 header length is expressed as count of 4-byte words.
            header_length: u8::try_from(IPV4_HEADER_LEN / 4)
                .wrap_err("IPv4 header length too large")?,

            // Set defaults.
            identification: 0,
            flags: Ipv4Flags::DontFragment,
            fragment_offset: 0,
            options: Vec::new(),
            ttl: 0xFF,

            // Total length and checksum to be calculated with payload.
            total_length: 0,
            checksum: 0,

            // Payload from handler.
            payload,
        };

        // Total length is `IPV4_HEADER_LEN + payload.len()`.
        // (This is true as long as packets aren't fragmented. See MTU.)
        params.total_length = u16::try_from(Ipv4Packet::packet_size(&params))
            .wrap_err("Ipv4 packet size too large")?;

        let mut packet = vec![0u8; Ipv4Packet::packet_size(&params)];
        let mut outgoing_packet =
            MutableIpv4Packet::new(&mut packet).ok_or_eyre("cannot build IPv4 packet")?;
        outgoing_packet.populate(&params);

        // Set header checksum.
        outgoing_packet.set_checksum(checksum(&outgoing_packet.to_immutable()));

        info!(?incoming_packet, ?outgoing_packet, "Sending Ipv4 response.");

        Ok(Some(packet))
    }

    fn should_intercept(&self, incoming_packet: &Ipv4Packet<'_>) -> bool {
        matches!(
            incoming_packet.get_next_level_protocol(),
            IpNextHeaderProtocol(253) | IpNextHeaderProtocols::Tcp
        ) && matches!(incoming_packet.get_destination(), SERVER_IP)
    }
}
