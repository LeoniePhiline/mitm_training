#![allow(unused_variables, dead_code)]

mod app_buffer;

use std::net::Ipv4Addr;

pub use app_buffer::AppBuffer;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ConnectionId(Ipv4Addr, u16, Ipv4Addr, u16);

impl ConnectionId {
    pub fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self(src_ip, src_port, dst_ip, dst_port)
    }

    #[inline]
    pub fn src_ip(&self) -> Ipv4Addr {
        self.0
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        self.1
    }

    #[inline]
    pub fn dst_ip(&self) -> Ipv4Addr {
        self.2
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.3
    }
}
