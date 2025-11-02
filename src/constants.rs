#![allow(unused_variables, dead_code)]

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

// Packet sizes
pub const ETHERNET_HEADER_SIZE: usize = EthernetPacket::minimum_packet_size();
pub const ARP_PACKET_SIZE: usize = ArpPacket::minimum_packet_size();
pub const IPV4_HEADER_LEN: usize = Ipv4Packet::minimum_packet_size();
pub const TCP_HEADER_LEN: usize = TcpPacket::minimum_packet_size();

// Common port numbers
pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;

// Environment configuration
// TODO: 0 - Replace the following constant with the ones from your environment
pub const MITM_IFACE_NAME: &str = "virbr1";
pub const VICTIM_IP: &str = "192.168.56.10";
pub const SERVER_IP: &str = "192.168.56.20";
pub const ECHO_PORT: u16 = 4000;
