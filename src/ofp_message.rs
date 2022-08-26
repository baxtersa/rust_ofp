use ofp_header::OfpHeader;

/// OpenFlow Message
///
/// Version-agnostic API for handling OpenFlow messages at the byte-buffer level.
pub trait OfpMessage {
    /// Return the byte-size of an `OfpMessage`.
    fn size_of(msg: &Self) -> usize;
    /// Create an `OfpHeader` for the given transaction id and OpenFlow message.
    fn header_of(xid: u32, msg: &Self) -> OfpHeader;
    /// Return a marshaled buffer containing an OpenFlow header and the message `msg`.
    fn marshal(xid: u32, msg: Self) -> Vec<u8>;
    /// Returns a pair `(u32, OfpMessage)` of the transaction id and OpenFlow message parsed from
    /// the given OpenFlow header `header`, and buffer `buf`.
    fn parse(header: &OfpHeader, buf: &[u8]) -> (u32, Self);
}
