use std::io::{BufRead, Cursor, Read};
use std::mem::size_of;
use byteorder::{BigEndian, ReadBytesExt};

use bits::test_bit;

pub fn bytes_of_mac(addr: u64) -> [u8; 6] {
    let mut arr = [0; 6];
    for i in 0..6 {
        arr[i] = ((addr >> (8 * i)) & 0xff) as u8;
    }
    arr
}

pub fn mac_of_bytes(addr: [u8; 6]) -> u64 {
    fn byte(u: &[u8; 6], i: usize) -> u64 {
        u[i] as u64
    };
    (byte(&addr, 0) << 8 * 5) | (byte(&addr, 1) << 8 * 4) | (byte(&addr, 2) << 8 * 3) |
    (byte(&addr, 3) << 8 * 2) | (byte(&addr, 4) << 8 * 1) | (byte(&addr, 5))
}

/// TCP Header flags.
pub struct TcpFlags {
    /// ECN-nonce concealment protection.
    pub ns: bool,
    /// Congestion window reduced.
    pub cwr: bool,
    /// ECN-Echo.
    pub ece: bool,
    /// Indicates the Urgent pointer field is significant.
    pub urg: bool,
    /// Indicates that the Acknowledgment field is significant.
    pub ack: bool,
    /// Asks to push the buffered data to the receiving application.
    pub psh: bool,
    /// Reset the connection.
    pub rst: bool,
    /// Synchronize sequence numbers.
    pub syn: bool,
    /// No more data from sender.
    pub fin: bool,
}

impl TcpFlags {
    fn of_int(d: u16) -> TcpFlags {
        TcpFlags {
            ns: test_bit(0, d as u64),
            cwr: test_bit(1, d as u64),
            ece: test_bit(2, d as u64),
            urg: test_bit(3, d as u64),
            ack: test_bit(4, d as u64),
            psh: test_bit(5, d as u64),
            rst: test_bit(6, d as u64),
            syn: test_bit(7, d as u64),
            fin: test_bit(8, d as u64),
        }
    }
}

/// TCP frame of a packet.
pub struct Tcp {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub ack: u32,
    pub offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub chksum: u16,
    pub urgent: u16,
    pub payload: Vec<u8>,
}

#[repr(packed)]
struct TcpNet(u16, u16, u32, u32, u16, u16, u16, u16);

impl Tcp {
    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Option<Tcp> {
        if bytes.get_ref().len() < size_of::<TcpNet>() {
            return None;
        }
        let src = bytes.read_u16::<BigEndian>().unwrap();
        let dst = bytes.read_u16::<BigEndian>().unwrap();
        let seq = bytes.read_u32::<BigEndian>().unwrap();
        let ack = bytes.read_u32::<BigEndian>().unwrap();
        let offset = bytes.read_u16::<BigEndian>().unwrap();
        let flags = TcpFlags::of_int(offset);
        let offset = (offset >> 12) as u8 & 0x0f;
        let window = bytes.read_u16::<BigEndian>().unwrap();
        let chksum = bytes.read_u16::<BigEndian>().unwrap();
        let urgent = bytes.read_u16::<BigEndian>().unwrap();
        let mut payload = vec![0; bytes.get_ref().len()];
        bytes.read_exact(&mut payload).unwrap();
        Some(Tcp {
            src: src,
            dst: dst,
            seq: seq,
            ack: ack,
            offset: offset,
            flags: flags,
            window: window,
            chksum: chksum,
            urgent: urgent,
            payload: payload,
        })
    }
}

/// UDP frame of a packet.
pub struct Udp {
    pub src: u16,
    pub dst: u16,
    pub chksum: u16,
    pub payload: Vec<u8>,
}

impl Udp {
    fn size_of() -> usize {
        8
    }

    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Option<Udp> {
        if bytes.get_ref().len() < Self::size_of() {
            return None;
        }
        let src = bytes.read_u16::<BigEndian>().unwrap();
        let dst = bytes.read_u16::<BigEndian>().unwrap();
        let chksum = bytes.read_u16::<BigEndian>().unwrap();
        let mut payload = vec![0; bytes.get_ref().len()];
        bytes.read_exact(&mut payload).unwrap();
        Some(Udp {
            src: src,
            dst: dst,
            chksum: chksum,
            payload: payload,
        })
    }
}

/// ICMP frame of a packet.
pub struct Icmp {
    pub typ: u8,
    pub code: u8,
    pub chksum: u16,
    pub payload: Vec<u8>,
}

impl Icmp {
    fn size_of() -> usize {
        4
    }

    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Option<Icmp> {
        if bytes.get_ref().len() < Self::size_of() {
            return None;
        }
        let typ = bytes.read_u8().unwrap();
        let code = bytes.read_u8().unwrap();
        let chksum = bytes.read_u16::<BigEndian>().unwrap();
        let mut payload = vec![0; bytes.get_ref().len()];
        bytes.read_exact(&mut payload).unwrap();
        Some(Icmp {
            typ: typ,
            code: code,
            chksum: chksum,
            payload: payload,
        })
    }
}

/// Represents packets at the transport protocol level, which are encapsulated
/// within the IPv4 payload. At present, we only support TCP, UDP, and ICMP
/// explicitly; otherwise, the raw bytes and IPv4 protocol number are provided.
pub enum Tp {
    Tcp(Tcp),
    Udp(Udp),
    Icmp(Icmp),
    Unparsable(u8, Vec<u8>),
}

/// The type of IPv4 flags.
pub struct Flags {
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

impl Flags {
    fn of_int(flags: u32) -> Flags {
        Flags {
            dont_fragment: test_bit(1, flags as u64),
            more_fragments: test_bit(2, flags as u64),
        }
    }
}

/// IPv4 frame of a packet.
pub struct Ip {
    pub tos: u8,
    pub ident: u16,
    pub flags: Flags,
    pub frag: u16,
    pub ttl: u8,
    pub chksum: u16,
    pub src: u32,
    pub dst: u32,
    pub options: Vec<u8>,
    pub tp: Tp,
}

#[repr(u8)]
enum IpProto {
    IpICMP = 0x01,
    IpTCP = 0x06,
    IpUDP = 0x11,
}

#[repr(packed)]
struct IpNet(u8, u8, u16, u16, u16, u8, u8, u16, u32, u32);

impl Ip {
    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Option<Ip> {
        if bytes.get_ref().len() < size_of::<IpNet>() {
            return None;
        }
        let vhl = bytes.read_u8().unwrap();
        if (vhl >> 4) != 4 {
            return None;
        }
        let ihl = vhl & 0x0f;
        let tos = bytes.read_u8().unwrap();
        bytes.consume(2);
        let ident = bytes.read_u16::<BigEndian>().unwrap();
        let frag = bytes.read_u16::<BigEndian>().unwrap();
        let flags = Flags::of_int((frag as u32) >> 13);
        let ttl = bytes.read_u8().unwrap();
        let proto = bytes.read_u8().unwrap();
        let chksum = bytes.read_u16::<BigEndian>().unwrap();
        let src = bytes.read_u32::<BigEndian>().unwrap();
        let dst = bytes.read_u32::<BigEndian>().unwrap();
        let options_len = (ihl * 4) as usize - size_of::<IpNet>();
        let mut options = vec![0; options_len];
        bytes.read_exact(&mut options).unwrap();
        let tp = match proto {
            t if t == (IpProto::IpICMP as u8) => {
                let bytes_ = bytes.get_ref().clone();
                let icmp = Icmp::parse(bytes);
                if icmp.is_some() {
                    Tp::Icmp(icmp.unwrap())
                } else {
                    Tp::Unparsable(proto, bytes_)
                }
            }
            t if t == (IpProto::IpTCP as u8) => {
                let bytes_ = bytes.get_ref().clone();
                let tcp = Tcp::parse(bytes);
                if tcp.is_some() {
                    Tp::Tcp(tcp.unwrap())
                } else {
                    Tp::Unparsable(proto, bytes_)
                }
            }
            t if t == (IpProto::IpUDP as u8) => {
                let bytes_ = bytes.get_ref().clone();
                let udp = Udp::parse(bytes);
                if udp.is_some() {
                    Tp::Udp(udp.unwrap())
                } else {
                    Tp::Unparsable(proto, bytes_)
                }
            }
            _ => Tp::Unparsable(proto, bytes.get_ref().clone()),
        };
        Some(Ip {
            tos: tos,
            ident: ident,
            flags: flags,
            frag: frag,
            ttl: ttl,
            chksum: chksum,
            src: src,
            dst: dst,
            options: options,
            tp: tp,
        })
    }
}

/// Address resolution protocol (ARP) packet payload.
pub enum Arp {
    Query(u64, u32, u32),
    Reply(u64, u32, u64, u32),
}

#[repr(packed)]
struct ArpNet(u16, u16, u8, u8, u16, [u8; 6], u32, [u8; 6], u32);

impl Arp {
    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Option<Arp> {
        if bytes.get_ref().len() < size_of::<ArpNet>() {
            return None;
        }
        bytes.consume(6);
        let oper = bytes.read_u16::<BigEndian>().unwrap();
        let mut sha: [u8; 6] = [0; 6];
        for i in 0..6 {
            sha[i] = bytes.read_u8().unwrap();
        }
        let spa = bytes.read_u32::<BigEndian>().unwrap();
        let mut tha: [u8; 6] = [0; 6];
        for i in 0..6 {
            tha[i] = bytes.read_u8().unwrap();
        }
        let tpa = bytes.read_u32::<BigEndian>().unwrap();
        match oper {
            0x0001 => Some(Arp::Query(mac_of_bytes(sha), spa, tpa)),
            0x0002 => Some(Arp::Reply(mac_of_bytes(sha), spa, mac_of_bytes(tha), tpa)),
            _ => None,
        }
    }
}

/// Represents a packet at the network protocol level.
pub enum Nw {
    Ip(Ip),
    Arp(Arp),
    Unparsable(u16, Vec<u8>),
}

/// Represents a packet at the ethernet protocol level.
pub struct Packet {
    pub dl_src: u64,
    pub dl_dst: u64,
    pub dl_vlan: Option<u16>,
    pub dl_vlan_dei: bool,
    pub dl_vlan_pcp: u8,
    pub nw: Nw,
}

#[repr(u16)]
enum EthTyp {
    EthTypIP = 0x0800,
    EthTypARP = 0x0806,
    EthTypVLAN = 0x8100,
}

impl Packet {
    pub fn parse(buf: &[u8]) -> Packet {
        let mut bytes = Cursor::new(buf.to_vec());
        let mut dst: [u8; 6] = [0; 6];
        let mut src: [u8; 6] = [0; 6];
        for i in 0..6 {
            dst[i] = bytes.read_u8().unwrap();
        }
        for i in 0..6 {
            src[i] = bytes.read_u8().unwrap();
        }
        let typ = bytes.read_u16::<BigEndian>().unwrap();
        let (tag, dei, pcp, typ) = match typ {
            t if t == (EthTyp::EthTypVLAN as u16) => {
                let tag_and_pcp = bytes.read_u16::<BigEndian>().unwrap();
                let tag = tag_and_pcp & 0xfff;
                let dei = (tag_and_pcp & 0x1000) > 0;
                let pcp = tag_and_pcp >> 13;
                let typ = bytes.read_u16::<BigEndian>().unwrap();
                (Some(tag), dei, pcp as u8, typ)
            }
            _ => (None, false, 0x0, typ),
        };
        let nw_header = match typ {
            t if t == (EthTyp::EthTypIP as u16) => {
                let bytes_ = bytes.get_ref().clone();
                let ip = Ip::parse(&mut bytes);
                if ip.is_some() {
                    Nw::Ip(ip.unwrap())
                } else {
                    Nw::Unparsable(typ, bytes_)
                }
            }
            t if t == (EthTyp::EthTypARP as u16) => {
                let bytes_ = bytes.get_ref().clone();
                let arp = Arp::parse(&mut bytes);
                if arp.is_some() {
                    Nw::Arp(arp.unwrap())
                } else {
                    Nw::Unparsable(typ, bytes_)
                }
            }
            _ => Nw::Unparsable(typ, bytes.into_inner()),
        };
        Packet {
            dl_src: mac_of_bytes(src),
            dl_dst: mac_of_bytes(dst),
            dl_vlan: tag,
            dl_vlan_dei: dei,
            dl_vlan_pcp: pcp,
            nw: nw_header,
        }
    }
}
