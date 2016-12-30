use std::net::TcpStream;
use ofp_message::OfpMessage;

/// OpenFlow Controller
///
/// Version-agnostic API for implementing an OpenFlow controller.
pub trait OfpController {
    /// OpenFlow message type supporting the same protocol version as the controller.
    type Message: OfpMessage;

    /// Send a message to the node associated with the given `TcpStream`.
    fn send_message(u32, Self::Message, &mut TcpStream);
    /// Perform handshake and begin loop reading incoming messages from client stream.
    fn handle_client_connected(&mut TcpStream);
}
