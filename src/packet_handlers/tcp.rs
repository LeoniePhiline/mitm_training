use std::{collections::HashMap, net::Ipv4Addr};

use color_eyre::{
    eyre::{bail, OptionExt, WrapErr},
    Result,
};
use pnet::packet::{
    tcp::{ipv4_checksum, MutableTcpPacket, Tcp, TcpFlags, TcpPacket},
    Packet,
};
use rand::Rng;
use tracing::{debug, event_enabled, info, trace, warn, Level};

use crate::{
    constants::{SERVER_IP, TCP_HEADER_LEN},
    models::{AppBuffer, ConnectionId},
    packet_handlers::{echo::EchoHandler, http::HttpHandler, tls::TlsHandler},
};

/// Represent the initial state of a TCP connection
#[derive(Clone, Debug, PartialEq)]
enum TcpState {
    /// A SYN has been received but we are waiting for an ACK
    InitialSynReceived,
    /// 3-way handshake has been completed, data can be exchanged on the connection
    Established,
    /// A side has asked to close the connection, we are waiting for the final ACK.
    Closing,
}

/// Hold the internal TCP connection information like its internal state, the current sequence numbers, the total data sent / received or the internal data buffer.
#[derive(Debug)]
struct TcpConnectionInfo {
    /// Internal TCP state
    pub state: TcpState,
    /// Buffer containing the received data
    pub buffer: AppBuffer,
    /// Current client sequence number
    pub client_seq_number: u32,
    /// Current server sequence number
    pub server_seq_number: u32,
    /// Total received data
    pub total_data_rx: usize,
    /// Total sent data
    pub total_data_tx: usize,
}

impl TcpConnectionInfo {
    pub fn new(client_seq_number: u32) -> Self {
        let mut rng = rand::rng();
        Self {
            state: TcpState::InitialSynReceived,
            server_seq_number: rng.random::<u32>(),
            client_seq_number,
            buffer: AppBuffer::new(client_seq_number + 1),
            total_data_rx: 0,
            total_data_tx: 0,
        }
    }
}

fn is_tcp_flag_set(flags: u8, expected_flag: u8) -> bool {
    flags & expected_flag == expected_flag
}

fn craft_tcp_packet(
    connection_id: &ConnectionId,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    // # Exercise 3.0
    //
    // Implement the crafting of a valid TCP packet with the given parameters.
    // Make sure the TCP checksum for the packet is correct.

    let payload = payload.unwrap_or_default();
    let params = Tcp {
        // Sending a TCP response, reversing direction.
        source: connection_id.dst_port(),
        destination: connection_id.src_port(),

        // Set options as provided.
        sequence,
        acknowledgement,
        flags,

        // TCP header length is expressed as count of 4-byte words.
        //
        // Using minimum header length is valid here, as we do not use the `options` field,
        // which would increase header length.
        data_offset: u8::try_from(TCP_HEADER_LEN / 4).wrap_err("TCP header length too large")?,

        // Set defaults.
        reserved: 0,
        window: 0x1000,
        urgent_ptr: 0,
        options: Vec::new(),

        // Checksum to be calculated with payload.
        checksum: 0,

        payload,
    };
    let mut packet = vec![0u8; TcpPacket::packet_size(&params)];
    let mut outgoing_packet =
        MutableTcpPacket::new(&mut packet).ok_or_eyre("cannot build TCP packet")?;
    outgoing_packet.populate(&params);

    // Set header checksum.
    outgoing_packet.set_checksum(ipv4_checksum(
        &outgoing_packet.to_immutable(),
        &connection_id.dst_ip(),
        &connection_id.src_ip(),
    ));

    info!(?outgoing_packet, "Crafted TCP packet.");

    Ok(packet)
}

pub struct TcpHandler {
    // K = (ip_src, port_src, ip_dst, port_dst) / V = Actual connection information
    active_connections: HashMap<ConnectionId, TcpConnectionInfo>,
    #[expect(unused)]
    http: HttpHandler,
    #[expect(unused)]
    tls: TlsHandler,
    echo: EchoHandler,
}

impl TcpHandler {
    pub fn new() -> Self {
        Self {
            active_connections: HashMap::new(),
            http: HttpHandler::new(),
            tls: TlsHandler::new(),
            echo: EchoHandler::new(),
        }
    }

    /// Handle a raw TCP packet.
    ///
    /// # Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(
        &mut self,
        packet: &[u8],
        options: &TcpHandlerOptions,
    ) -> Result<Option<Vec<u8>>> {
        trace!("Received TCP packet...");

        let Some(incoming_packet) = TcpPacket::new(packet) else {
            bail!("cannot create tcp packet...")
        };

        let src_ip = options.src_ip;
        let dst_ip = options.dst_ip;

        let dst_port = incoming_packet.get_destination();
        let src_port = incoming_packet.get_source();
        let flags = incoming_packet.get_flags();
        let client_seq_number = incoming_packet.get_sequence();
        let payload = incoming_packet.payload();

        if !self.should_intercept(dst_ip, &incoming_packet) {
            return Ok(None);
        }

        debug!("Found target to intercept: {dst_ip}:{dst_port}");

        let syn_flag_set = is_tcp_flag_set(flags, TcpFlags::SYN);
        let ack_flag_set = is_tcp_flag_set(flags, TcpFlags::ACK);
        let psh_flag_set = is_tcp_flag_set(flags, TcpFlags::PSH);
        let fin_flag_set = is_tcp_flag_set(flags, TcpFlags::FIN);
        let rst_flag_set = is_tcp_flag_set(flags, TcpFlags::RST);

        if event_enabled!(Level::TRACE) {
            let flags = [
                (syn_flag_set, "SYN"),
                (ack_flag_set, "ACK"),
                (psh_flag_set, "PSH"),
                (fin_flag_set, "FIN"),
                (rst_flag_set, "RST"),
            ];

            let flags_str = flags
                .iter()
                .filter_map(|(set, name)| if *set { Some(*name) } else { None })
                .collect::<Vec<_>>()
                .join("|");

            trace!("TCP flags: |{flags_str}|");
        }

        let connection_id = ConnectionId::new(src_ip, src_port, dst_ip, dst_port);

        if syn_flag_set {
            trace!("[+] SYN from {src_ip}:{src_port}");
            trace!(
                "-> SYN -> SEQ: {} - ACK {}",
                client_seq_number,
                incoming_packet.get_acknowledgement()
            );

            return self.handle_tcp_syn(&connection_id, client_seq_number);
        }

        if rst_flag_set {
            trace!("received RST from {src_ip}:{src_port}");
            return self.handle_tcp_rst(&connection_id);
        }

        if fin_flag_set {
            trace!("received FIN from {src_ip}:{src_port}");
            return self.handle_tcp_fin(&connection_id, client_seq_number);
        }

        if ack_flag_set {
            trace!(
                "RECV -> ACK | SEQ: {} - ACK {} - data_len={}",
                incoming_packet.get_sequence(),
                incoming_packet.get_acknowledgement(),
                payload.len()
            );
            if let Some(response_packet) = self.handle_tcp_ack(
                &connection_id,
                incoming_packet.get_sequence(),
                incoming_packet.get_acknowledgement(),
            )? {
                // In case the client sent an invalid packet:
                // Send `ACK` + `RST` response packet to force-close the connection.
                return Ok(Some(response_packet));
            }
        }

        // data is sometimes sent without a PSH...
        if psh_flag_set || !payload.is_empty() {
            trace!("[DATA] SEQ={} | LEN={}", client_seq_number, payload.len());
            return self.handle_tcp_psh(&connection_id, client_seq_number, payload);
        }

        Ok(None)
    }

    fn should_intercept(&self, dst_ip: Ipv4Addr, incoming_packet: &TcpPacket<'_>) -> bool {
        dst_ip == SERVER_IP && incoming_packet.get_destination() == 4000
    }

    fn handle_tcp_syn(
        &mut self,
        connection_id: &ConnectionId,
        client_seq_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        // # Exercise 3.1
        //
        // Implement the handling of a packet containing a TCP SYN flag. This
        // function performs an early return in our TCP state machine, so no
        // other handler will be called even if the incoming packet contains
        // additional flags.

        if self.active_connections.contains_key(connection_id) {
            warn!("Invalid SYN received: connection already exists. Force-closing connection.");

            // Force-close the connection.
            let mut rng = rand::rng();
            let response_packet = craft_tcp_packet(
                connection_id,
                rng.random::<u32>(),
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        }

        let mut connection = TcpConnectionInfo::new(client_seq_number);

        // Update client sequence number with phantom byte received.
        connection.client_seq_number = connection.client_seq_number.wrapping_add(1);

        debug!(?connection_id, ?connection, "Acknowledging connection.");

        let response_packet = craft_tcp_packet(
            connection_id,
            connection.server_seq_number,
            connection.client_seq_number,
            TcpFlags::SYN | TcpFlags::ACK,
            None,
        )?;

        // Update server sequence number with phantom byte sent.
        // We are assuming all messages sent to be received.
        // Therefore, we can track the expected ACK before receiving acknowledgement from the other side.
        //
        // In real-life TCP handing, we would instead track each packet's `ACK` state
        // and resend if not acknowledged after a timeout.
        connection.server_seq_number = connection.server_seq_number.wrapping_add(1);

        self.active_connections
            .insert(connection_id.to_owned(), connection);

        Ok(Some(response_packet))
    }

    fn handle_tcp_ack(
        &mut self,
        connection_id: &ConnectionId,
        client_seq_number: u32,
        client_ack_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        // # Exercise 3.2
        //
        // Implement the handling of a packet containing a TCP ACK flag. This
        // function can be called alongside `handle_tcp_psh`.

        let Some(connection) = self.active_connections.get_mut(connection_id) else {
            warn!("Invalid ACK received: connection not found. Force-closing connection.");

            // Force-close the connection.
            let mut rng = rand::rng();
            let response_packet = craft_tcp_packet(
                connection_id,
                rng.random::<u32>(),
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        };

        // Verify server sequence acknowledgement.
        //
        // We are assuming all messages sent to be received.
        // Therefore, we already tracked the expected ACK before having received acknowledgement from the other side.
        //
        // In real-life TCP handing, we would instead track each packet's `ACK` state
        // and resend if not acknowledged after a timeout.
        if client_ack_number != connection.server_seq_number {
            warn!(
                "Invalid ACK received: acknowledgement is {client_ack_number}, expected {}. Force-closing connection.",
                connection.server_seq_number
            );

            // Force-close the connection.
            let response_packet = craft_tcp_packet(
                connection_id,
                connection.server_seq_number,
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        }

        if connection.state == TcpState::InitialSynReceived {
            connection.state = TcpState::Established;
            debug!(?connection_id, ?connection, "Connection established.");
        }

        if connection.state == TcpState::Closing {
            self.active_connections.remove(connection_id);
            debug!(?connection_id, "Connection Closed.");
        }

        Ok(None)
    }

    fn handle_tcp_psh(
        &mut self,
        connection_id: &ConnectionId,
        client_seq_number: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // # Exercise 3.3
        //
        // Implement the handling of a packet containing a TCP PSH flag. You
        // should use `TcpConnectionInfo.buffer` to store the received payload.
        // This should call another handler's `.handle_packet()` function
        // depending on the payload type.
        // Once you have implemented the logic for handling any TCP packet,
        // the payload type.

        let Some(connection) = self.active_connections.get_mut(connection_id) else {
            warn!("Invalid PSH received: connection not found. Force-closing connection.");

            // Force-close the connection.
            let mut rng = rand::rng();
            let response_packet = craft_tcp_packet(
                connection_id,
                rng.random::<u32>(),
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        };

        if client_seq_number != connection.client_seq_number {
            warn!(
                "Invalid PSH received: sequence number is {client_seq_number}, expected {}. Force-closing connection.",
                connection.client_seq_number
            );

            // Force-close the connection.
            let response_packet = craft_tcp_packet(
                connection_id,
                connection.server_seq_number,
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        }

        trace!("Data received: {}", String::from_utf8_lossy(payload));

        connection.total_data_rx = connection.total_data_rx.saturating_add(payload.len());
        connection.buffer.insert(client_seq_number, payload);

        // Update client sequence number with bytes received.
        connection.client_seq_number =
            // Intentionally truncating (wrap-around) cast from `usize` to `u32`.
            (connection.client_seq_number as usize).wrapping_add(payload.len()) as u32;

        debug!(?connection_id, ?connection, "Data received.");

        let payload = match connection_id.dst_port() {
            4000 => self.echo.handle_packet(&mut connection.buffer, ()),
            _ => Ok(None),
        }?;

        let mut flags = TcpFlags::ACK;
        let mut payload_len = 0;

        if let Some(payload) = &payload {
            // The test expects a payload echo.
            // Therefore, we not only `ACK` but also `PSH`,
            // returning the payload received.
            payload_len = payload.len();
            connection.total_data_tx = connection.total_data_tx.saturating_add(payload_len);

            flags |= TcpFlags::PSH;
        }

        let response_packet = craft_tcp_packet(
            connection_id,
            connection.server_seq_number,
            connection.client_seq_number,
            flags,
            payload,
        )?;

        // Update server sequence number with bytes sent.
        // We are assuming all messages sent to be received.
        // Therefore, we can track the expected ACK before receiving acknowledgement from the other side.
        //
        // In real-life TCP handing, we would instead track each packet's `ACK` state
        // and resend if not acknowledged after a timeout.
        connection.server_seq_number =
            // Intentionally truncating (wrap-around) cast from `usize` to `u32`.
            (connection.server_seq_number as usize).wrapping_add(payload_len) as u32;

        Ok(Some(response_packet))
    }

    fn handle_tcp_fin(
        &mut self,
        connection_id: &ConnectionId,
        client_seq_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        // # Exercise 3.5
        //
        // Implement the handling of a packet containing a TCP FIN flag. This
        // function performs an early return in our TCP state machine, so no
        // other handler will be called even if the incoming packet contains
        // additional flags.
        // Once correctly implemented, you should pass test case #3.

        let Some(connection) = self.active_connections.get_mut(connection_id) else {
            warn!("Invalid FIN received: connection not found. Force-closing connection.");

            // Force-close the connection.
            let mut rng = rand::rng();
            let response_packet = craft_tcp_packet(
                connection_id,
                rng.random::<u32>(),
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        };

        if client_seq_number != connection.client_seq_number {
            warn!(
                "Invalid FIN received: sequence number is {client_seq_number}, expected {}. Force-closing connection.",
                connection.client_seq_number
            );

            // Force-close the connection.
            let response_packet = craft_tcp_packet(
                connection_id,
                connection.server_seq_number,
                client_seq_number.wrapping_add(1),
                TcpFlags::ACK | TcpFlags::RST,
                None,
            )?;
            return Ok(Some(response_packet));
        }

        // Update client sequence number with phantom byte received.
        connection.client_seq_number = connection.client_seq_number.wrapping_add(1);

        debug!(
            ?connection_id,
            ?connection,
            "Acknowledging connection close."
        );

        connection.state = TcpState::Closing;

        let response_packet = craft_tcp_packet(
            connection_id,
            connection.server_seq_number,
            connection.client_seq_number,
            TcpFlags::FIN | TcpFlags::ACK,
            None,
        )?;

        // Update server sequence number with phantom byte sent.
        // We are assuming all messages sent to be received.
        // Therefore, we can track the expected ACK before receiving acknowledgement from the other side.
        //
        // In real-life TCP handing, we would instead track each packet's `ACK` state
        // and resend if not acknowledged after a timeout.
        connection.server_seq_number = connection.server_seq_number.wrapping_add(1);

        Ok(Some(response_packet))
    }

    fn handle_tcp_rst(&mut self, connection_id: &ConnectionId) -> Result<Option<Vec<u8>>> {
        // # Exercise 3.6 - Optional
        //
        // Implement the handling of a packet containing a TCP RST flag. This
        // function performs an early return in our TCP state machine, so no
        // other handler will be called even if the incoming packet contains
        // additional flags.

        let connection = self.active_connections.remove(connection_id);

        if connection.is_none() {
            warn!("Invalid RST received: connection not found.");
            // No `RST` to be sent, as the client already considers the connection closed.
            return Ok(None);
        };

        Ok(None)
    }
}

pub struct TcpHandlerOptions {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}
