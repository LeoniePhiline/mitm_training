use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{Result, anyhow, bail};
use log::LevelFilter;
use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use rand::Rng;

use crate::constants::{ECHO_PORT, HTTP_PORT, HTTPS_PORT, TCP_HEADER_LEN};
use crate::models::{AppBuffer, ConnectionId};
use crate::packet_handlers::echo::EchoHandler;
use crate::packet_handlers::http::{HttpHandler, HttpHandlerOptions};
use crate::packet_handlers::tls::{TlsHandler, TlsHandlerOptions};

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
    seq: u32,
    ack: u32,
    flags: u8,
    data: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    log::trace!("OUTPUT -> SEQ: {seq} - ACK {ack}");

    let data_len = data.as_ref().map_or(0, Vec::len);
    let packet_len: usize = TCP_HEADER_LEN + data_len;

    let mut packet = vec![0u8; packet_len];

    let mut tcp_packet =
        MutableTcpPacket::new(&mut packet).ok_or(anyhow!("cannot build tcp packet"))?;
    tcp_packet.set_source(connection_id.dst_port()); // Source port for the response packet is the dest port of the connection ID
    tcp_packet.set_destination(connection_id.src_port());
    tcp_packet.set_sequence(seq);
    tcp_packet.set_acknowledgement(ack);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(flags);
    tcp_packet.set_window(64240);

    if let Some(data_bytes) = data {
        tcp_packet.set_payload(&data_bytes);
    }

    let checksum = pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &connection_id.dst_ip(),
        &connection_id.src_ip(),
    );
    tcp_packet.set_checksum(checksum);

    Ok(packet)
}

pub struct TcpHandler {
    // K = (ip_src, port_src, ip_dst, port_dst) / V = Actual connection information
    active_connections: HashMap<ConnectionId, TcpConnectionInfo>,
    http: HttpHandler,
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
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(
        &mut self,
        packet: &[u8],
        options: &TcpHandlerOptions,
    ) -> Result<Option<Vec<u8>>> {
        log::trace!("received TCP packet...");

        let Some(inbound_tcp_packet) = TcpPacket::new(packet) else {
            bail!("cannot create tcp packet...")
        };

        let src_ip = options.src_ip;
        let dst_ip = options.dst_ip;

        let dst_port = inbound_tcp_packet.get_destination();
        let src_port = inbound_tcp_packet.get_source();
        let flags = inbound_tcp_packet.get_flags();
        let seq = inbound_tcp_packet.get_sequence();
        let data = inbound_tcp_packet.payload();

        if !self.should_intercept(dst_port) {
            return Ok(None);
        }

        log::debug!("Found target to intercept: {dst_ip}:{dst_port}");

        let syn_flag_set = is_tcp_flag_set(flags, TcpFlags::SYN);
        let ack_flag_set = is_tcp_flag_set(flags, TcpFlags::ACK);
        let psh_flag_set = is_tcp_flag_set(flags, TcpFlags::PSH);
        let fin_flag_set = is_tcp_flag_set(flags, TcpFlags::FIN);
        let rst_flag_set = is_tcp_flag_set(flags, TcpFlags::RST);

        if log::log_enabled!(log::Level::Trace) && log::max_level() == LevelFilter::Trace {
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

            log::trace!("TCP flags: |{flags_str}|");
        }

        let connection_id = ConnectionId::new(src_ip, src_port, dst_ip, dst_port);

        if rst_flag_set {
            log::trace!("received RST from {src_ip}:{src_port}");
            return self.handle_tcp_rst(&connection_id);
        }

        if fin_flag_set {
            log::trace!("received FIN from {src_ip}:{src_port}");
            return self.handle_tcp_fin(&connection_id, seq);
        }

        if syn_flag_set {
            log::trace!("[+] SYN from {src_ip}:{src_port}");
            log::trace!(
                "-> SYN -> SEQ: {} - ACK {}",
                seq,
                inbound_tcp_packet.get_acknowledgement()
            );

            return self.handle_tcp_syn(&connection_id, seq);
        }

        if ack_flag_set {
            log::trace!(
                "RECV -> ACK | SEQ: {} - ACK {} - data_len={}",
                inbound_tcp_packet.get_sequence(),
                inbound_tcp_packet.get_acknowledgement(),
                data.len()
            );
            self.handle_tcp_ack(&connection_id, inbound_tcp_packet.get_acknowledgement())?;
        }

        // data is sometimes sent without a PSH...
        if psh_flag_set || !data.is_empty() {
            log::trace!("[DATA] SEQ={} | LEN={}", seq, data.len());
            return self.handle_tcp_psh(&connection_id, seq, data);
        }

        Ok(None)
    }

    fn should_intercept(&self, destination_port: u16) -> bool {
        [HTTP_PORT, HTTPS_PORT, ECHO_PORT].contains(&destination_port)
    }

    fn handle_tcp_syn(
        &mut self,
        connection_id: &ConnectionId,
        seq_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        let conn = TcpConnectionInfo::new(seq_number);
        let server_initial_seq = conn.server_seq_number;

        self.active_connections
            .insert(connection_id.to_owned(), conn);

        // Send SYN-ACK
        Ok(Some(craft_tcp_packet(
            connection_id,
            server_initial_seq,
            seq_number + 1,
            TcpFlags::SYN | TcpFlags::ACK,
            None,
        )?))
    }

    fn handle_tcp_ack(&mut self, connection_id: &ConnectionId, ack: u32) -> Result<()> {
        let Some(conn) = self.active_connections.get_mut(connection_id) else {
            // We do not have this connection in our active connections HashMap.
            // This is likely due to:
            // - a connection intercepted on-the-fly
            // - a ACK received after a FIN-ACK (probably because of a retransmission) has been received (and thus the connection removed)
            // We are thus not treating this behaviour as an error.
            log::error!(
                "received gratuitous ACK from {}:{}",
                connection_id.src_ip(),
                connection_id.src_port()
            );

            return Ok(());
        };

        match conn.state {
            TcpState::InitialSynReceived => {
                // This is the final 3-way handshake ACK
                if ack != conn.server_seq_number + 1 {
                    bail!(
                        "ACK mismatch! Expected {}, got {}",
                        conn.server_seq_number,
                        ack
                    )
                }

                log::info!(
                    "opened tcp connection with {}:{}",
                    connection_id.src_ip(),
                    connection_id.src_port()
                );

                conn.state = TcpState::Established;
                conn.server_seq_number = ack;
            }
            TcpState::Established => {}
            TcpState::Closing => {
                let conn = self.active_connections.remove(connection_id);
                let (total_amount_rx, total_amount_tx) = conn
                    .map(|c| (c.total_data_rx, c.total_data_tx))
                    .unwrap_or_default();

                log::info!(
                    "closed connection with {}:{}. rx_data={total_amount_rx} tx_data={total_amount_tx}",
                    connection_id.src_ip(),
                    connection_id.src_port()
                );
            }
        }

        Ok(())
    }

    fn handle_tcp_psh(
        &mut self,
        connection_id: &ConnectionId,
        seq_number: u32,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let Some(conn) = self.active_connections.get_mut(connection_id) else {
            bail!("no active connection found");
        };

        // Check for tcp retransmissions
        if seq_number < conn.client_seq_number {
            log::debug!("received old client number, this is likely a retransmission :/");
            return Ok(None);
        }

        // Buffer the data
        conn.buffer.insert(seq_number, data);

        // Add total data amout for this conn
        conn.total_data_rx += data.len();

        conn.client_seq_number = seq_number + data.len() as u32;

        let res = match connection_id.dst_port() {
            HTTP_PORT => self.http.handle_packet(
                &mut conn.buffer,
                &HttpHandlerOptions {
                    is_underlying_layer_encrypted: false,
                    conn_id: connection_id.clone(),
                },
            )?,
            HTTPS_PORT => self.tls.handle_packet(
                &mut conn.buffer,
                &TlsHandlerOptions {
                    conn_id: connection_id.clone(),
                },
            )?,
            ECHO_PORT => self.echo.handle_packet(&mut conn.buffer, ())?,
            p => bail!("unhandled proto on port {p}..."),
        };

        match res {
            None => Ok(Some(craft_tcp_packet(
                connection_id,
                conn.server_seq_number,
                conn.client_seq_number,
                TcpFlags::ACK,
                None,
            )?)),
            Some(payload) => {
                let payload_len = payload.len();
                conn.total_data_tx += payload_len;
                // Send response
                let res = craft_tcp_packet(
                    connection_id,
                    conn.server_seq_number,
                    conn.client_seq_number,
                    TcpFlags::ACK | TcpFlags::PSH,
                    Some(payload.to_vec()),
                )?;

                // Update our server seq number correctly
                conn.server_seq_number += payload_len as u32;

                log::trace!(
                    "SENT -> SEQ: {} - ACK: {} ({} bytes)",
                    conn.server_seq_number - payload_len as u32,
                    conn.client_seq_number,
                    payload_len
                );

                Ok(Some(res))
            }
        }
    }

    fn handle_tcp_fin(
        &mut self,
        connection_id: &ConnectionId,
        seq_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        let Some(conn) = self.active_connections.get_mut(connection_id) else {
            bail!("no active connection found");
        };

        conn.state = TcpState::Closing;

        Ok(Some(craft_tcp_packet(
            connection_id,
            conn.server_seq_number,
            seq_number + 1,
            TcpFlags::FIN | TcpFlags::ACK,
            None,
        )?))
    }

    fn handle_tcp_rst(&mut self, connection_id: &ConnectionId) -> Result<Option<Vec<u8>>> {
        self.active_connections.remove(connection_id);
        Ok(None)
    }
}

pub struct TcpHandlerOptions {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}
