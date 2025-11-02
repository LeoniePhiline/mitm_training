// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use color_eyre::Result;

use crate::packet_handlers::ipv4_test1::Ipv4Test1Handler;
use crate::packet_handlers::tcp::TcpHandler;

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
        // TODO: Exercise 2.1
        // Implement the handling of an IPv4 packet. This should call another
        // handler's `.handle_packet()` function depending on the payload type.
        // Once you have implemented the logic for handling any IPv4 packet,
        // move on to `IPv4TestHandler` to implement the echo service.

        if !self.should_intercept() {
            return Ok(None);
        }

        Ok(None)
    }

    fn should_intercept(&self) -> bool {
        // TODO: implement your custom interception logic here. You may pass
        // additional parameters to this function.
        true
    }
}
