use std::io::{BufRead, Cursor, Read, Write};
use std::mem::{size_of, transmute};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use bits::*;

/// OpenFlow 1.0 message type codes, used by headers to identify meaning of the rest of a message.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum MsgCode {
    Hello,
    Error,
    EchoReq,
    EchoResp,
    Vendor,
    FeaturesReq,
    FeaturesResp,
    GetConfigReq,
    GetConfigResp,
    SetConfig,
    PacketIn,
    FlowRemoved,
    PortStatus,
    PacketOut,
    FlowMod,
    PortMod,
    StatsReq,
    StatsResp,
    BarrierReq,
    BarrierResp,
    QueueGetConfigReq,
    QueueGetConfigResp,
}

/// Common API for message types implementing OpenFlow Message Codes (see `MsgCode` enum).
pub trait MessageType {
    /// Return the byte-size of a message.
    fn size_of(&Self) -> usize;
    /// Parse a buffer into a message.
    fn parse(buf: &[u8]) -> Self;
    /// Marshal a message into a `u8` buffer.
    fn marshal(Self, &mut Vec<u8>);
}

pub struct Mask<T> {
    pub value: T,
    pub mask: Option<T>,
}

/// Fields to match against flows.
pub struct Pattern {
    pub dl_src: Option<[u8; 6]>,
    pub dl_dst: Option<[u8; 6]>,
    pub dl_typ: Option<u16>,
    pub dl_vlan: Option<Option<u16>>,
    pub dl_vlan_pcp: Option<u8>,
    pub nw_src: Option<Mask<u32>>,
    pub nw_dst: Option<Mask<u32>>,
    pub nw_proto: Option<u8>,
    pub nw_tos: Option<u8>,
    pub tp_src: Option<u16>,
    pub tp_dst: Option<u16>,
    pub in_port: Option<u16>,
}

struct Wildcards {
    in_port: bool,
    dl_vlan: bool,
    dl_src: bool,
    dl_dst: bool,
    dl_type: bool,
    nw_proto: bool,
    tp_src: bool,
    tp_dst: bool,
    nw_src: u32,
    nw_dst: u32,
    dl_vlan_pcp: bool,
    nw_tos: bool,
}

impl Wildcards {
    fn set_nw_mask(f: u32, offset: usize, v: u32) -> u32 {
        let value = (0x3f & v) << offset;
        f | value
    }

    fn get_nw_mask(f: u32, offset: usize) -> u32 {
        (f >> offset) & 0x3f
    }

    fn mask_bits(x: &Option<Mask<u32>>) -> u32 {
        match *x {
            None => 32,
            Some(ref x) => {
                match x.mask {
                    None => 0,
                    Some(m) => m,
                }
            }
        }
    }

    fn marshal(w: Wildcards, bytes: &mut Vec<u8>) {
        let ret = 0u32;
        let ret = bit(0, ret as u64, w.in_port) as u32;
        let ret = bit(1, ret as u64, w.dl_vlan) as u32;
        let ret = bit(2, ret as u64, w.dl_src) as u32;
        let ret = bit(3, ret as u64, w.dl_dst) as u32;
        let ret = bit(4, ret as u64, w.dl_type) as u32;
        let ret = bit(5, ret as u64, w.nw_proto) as u32;
        let ret = bit(6, ret as u64, w.tp_src) as u32;
        let ret = bit(7, ret as u64, w.tp_dst) as u32;
        let ret = Wildcards::set_nw_mask(ret, 8, w.nw_src);
        let ret = Wildcards::set_nw_mask(ret, 14, w.nw_dst);
        let ret = bit(20, ret as u64, w.dl_vlan_pcp) as u32;
        let ret = bit(21, ret as u64, w.nw_tos) as u32;
        bytes.write_u32::<BigEndian>(ret).unwrap()
    }

    fn parse(bits: u32) -> Wildcards {
        Wildcards {
            in_port: test_bit(0, bits as u64),
            dl_vlan: test_bit(1, bits as u64),
            dl_src: test_bit(2, bits as u64),
            dl_dst: test_bit(3, bits as u64),
            dl_type: test_bit(4, bits as u64),
            nw_proto: test_bit(5, bits as u64),
            tp_src: test_bit(6, bits as u64),
            tp_dst: test_bit(7, bits as u64),
            nw_src: Wildcards::get_nw_mask(bits, 8),
            nw_dst: Wildcards::get_nw_mask(bits, 14),
            dl_vlan_pcp: test_bit(20, bits as u64),
            nw_tos: test_bit(21, bits as u64),
        }
    }
}

impl Pattern {
    pub fn match_all() -> Pattern {
        Pattern {
            dl_src: None,
            dl_dst: None,
            dl_typ: None,
            dl_vlan: None,
            dl_vlan_pcp: None,
            nw_src: None,
            nw_dst: None,
            nw_proto: None,
            nw_tos: None,
            tp_src: None,
            tp_dst: None,
            in_port: None,
        }
    }

    fn wildcards_of_pattern(m: &Pattern) -> Wildcards {
        Wildcards {
            in_port: m.in_port.is_none(),
            dl_vlan: m.dl_vlan.is_none(),
            dl_src: m.dl_src.is_none(),
            dl_dst: m.dl_dst.is_none(),
            dl_type: m.dl_typ.is_none(),
            nw_proto: m.nw_proto.is_none(),
            tp_src: m.tp_src.is_none(),
            tp_dst: m.tp_dst.is_none(),
            nw_src: Wildcards::mask_bits(&m.nw_src),
            nw_dst: Wildcards::mask_bits(&m.nw_dst),
            dl_vlan_pcp: m.dl_vlan_pcp.is_none(),
            nw_tos: m.nw_tos.is_none(),
        }
    }

    fn size_of(_: &Pattern) -> usize {
        size_of::<OfpMatch>()
    }

    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Pattern {
        let w = Wildcards::parse(bytes.read_u32::<BigEndian>().unwrap());
        let in_port = if w.in_port {
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        let dl_src = if w.dl_src {
            None
        } else {
            let mut arr: [u8; 6] = [0; 6];
            for i in 0..6 {
                arr[i] = bytes.read_u8().unwrap();
            }
            Some(arr)
        };
        let dl_dst = if w.dl_dst {
            None
        } else {
            let mut arr: [u8; 6] = [0; 6];
            for i in 0..6 {
                arr[i] = bytes.read_u8().unwrap();
            }
            Some(arr)
        };
        let dl_vlan = if w.dl_vlan {
            None
        } else {
            let vlan = bytes.read_u16::<BigEndian>().unwrap();
            if vlan == 0xfff {
                Some(None)
            } else {
                Some(Some(vlan))
            }
        };
        let dl_vlan_pcp = if w.dl_vlan_pcp {
            None
        } else {
            Some(bytes.read_u8().unwrap())
        };
        bytes.consume(1);
        let dl_typ = if w.dl_type {
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        let nw_tos = if w.nw_tos {
            None
        } else {
            Some(bytes.read_u8().unwrap())
        };
        let nw_proto = if w.nw_proto {
            None
        } else {
            Some(bytes.read_u8().unwrap())
        };
        bytes.consume(2);
        let nw_src = if w.nw_src >= 32 {
            None
        } else if w.nw_src == 0 {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: None,
            })
        } else {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: Some(w.nw_src),
            })
        };
        let nw_dst = if w.nw_dst >= 32 {
            None
        } else if w.nw_dst == 0 {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: None,
            })
        } else {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: Some(w.nw_src),
            })
        };
        let tp_src = if w.tp_src {
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        let tp_dst = if w.tp_dst {
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        Pattern {
            dl_src: dl_src,
            dl_dst: dl_dst,
            dl_typ: dl_typ,
            dl_vlan: dl_vlan,
            dl_vlan_pcp: dl_vlan_pcp,
            nw_src: nw_src,
            nw_dst: nw_dst,
            nw_proto: nw_proto,
            nw_tos: nw_tos,
            tp_src: tp_src,
            tp_dst: tp_dst,
            in_port: in_port,
        }
    }

    fn marshal(p: Pattern, bytes: &mut Vec<u8>) {
        let w = Pattern::wildcards_of_pattern(&p);
        Wildcards::marshal(w, bytes);
        bytes.write_u16::<BigEndian>(p.in_port.unwrap_or(0)).unwrap();
        for i in 0..6 {
            bytes.write_u8(p.dl_src.unwrap_or([0; 6])[i]).unwrap();
        }
        for i in 0..6 {
            bytes.write_u8(p.dl_dst.unwrap_or([0; 6])[i]).unwrap();
        }
        let vlan = match p.dl_vlan {
            Some(Some(v)) => v,
            Some(None) => 0xffff,
            None => 0xffff,
        };
        bytes.write_u16::<BigEndian>(vlan).unwrap();
        bytes.write_u8(p.dl_vlan_pcp.unwrap_or(0)).unwrap();
        bytes.write_u8(0).unwrap();
        bytes.write_u16::<BigEndian>(p.dl_typ.unwrap_or(0)).unwrap();
        bytes.write_u8(p.nw_tos.unwrap_or(0)).unwrap();
        bytes.write_u16::<BigEndian>(0).unwrap();
        bytes.write_u8(p.nw_proto.unwrap_or(0)).unwrap();

        bytes.write_u32::<BigEndian>(p.nw_src
                .unwrap_or(Mask {
                    value: 0,
                    mask: None,
                })
                .value)
            .unwrap();
        bytes.write_u32::<BigEndian>(p.nw_dst
                .unwrap_or(Mask {
                    value: 0,
                    mask: None,
                })
                .value)
            .unwrap();

        bytes.write_u16::<BigEndian>(p.tp_src.unwrap_or(0)).unwrap();
        bytes.write_u16::<BigEndian>(p.tp_dst.unwrap_or(0)).unwrap();
    }
}

#[repr(packed)]
struct OfpMatch(u32, u16, [u8; 6], [u8; 6], u16, u8, u8, u16, u8, u8, u16, u32, u32, u16, u16);

/// Port behavior.
#[derive(Copy, Clone)]
pub enum PseudoPort {
    PhysicalPort(u16),
    InPort,
    Table,
    Normal,
    Flood,
    AllPorts,
    Controller(u64),
    Local,
}

#[repr(u16)]
enum OfpPort {
    OFPPMax = 0xff00,
    OFPPInPort = 0xfff8,
    OFPPTable = 0xfff9,
    OFPPNormal = 0xfffa,
    OFPPFlood = 0xfffb,
    OFPPAll = 0xfffc,
    OFPPController = 0xfffd,
    OFPPLocal = 0xfffe,
    OFPPNone = 0xffff,
}

impl PseudoPort {
    fn of_int(p: u16) -> Option<PseudoPort> {
        if (OfpPort::OFPPNone as u16) == p {
            None
        } else {
            Some(PseudoPort::make(p, 0))
        }
    }

    fn make(p: u16, len: u64) -> PseudoPort {
        match p {
            p if p == (OfpPort::OFPPInPort as u16) => PseudoPort::InPort,
            p if p == (OfpPort::OFPPTable as u16) => PseudoPort::Table,
            p if p == (OfpPort::OFPPNormal as u16) => PseudoPort::Normal,
            p if p == (OfpPort::OFPPFlood as u16) => PseudoPort::Flood,
            p if p == (OfpPort::OFPPAll as u16) => PseudoPort::AllPorts,
            p if p == (OfpPort::OFPPController as u16) => PseudoPort::Controller(len),
            p if p == (OfpPort::OFPPLocal as u16) => PseudoPort::Local,
            _ => {
                if p <= (OfpPort::OFPPMax as u16) {
                    PseudoPort::PhysicalPort(p)
                } else {
                    panic!("Unsupported port number {}", p)
                }
            }
        }
    }

    fn marshal(pp: PseudoPort, bytes: &mut Vec<u8>) {
        match pp {
            PseudoPort::PhysicalPort(p) => bytes.write_u16::<BigEndian>(p).unwrap(),
            PseudoPort::InPort => bytes.write_u16::<BigEndian>(OfpPort::OFPPInPort as u16).unwrap(),
            PseudoPort::Table => bytes.write_u16::<BigEndian>(OfpPort::OFPPTable as u16).unwrap(),
            PseudoPort::Normal => bytes.write_u16::<BigEndian>(OfpPort::OFPPNormal as u16).unwrap(),
            PseudoPort::Flood => bytes.write_u16::<BigEndian>(OfpPort::OFPPFlood as u16).unwrap(),
            PseudoPort::AllPorts => bytes.write_u16::<BigEndian>(OfpPort::OFPPAll as u16).unwrap(),
            PseudoPort::Controller(_) => {
                bytes.write_u16::<BigEndian>(OfpPort::OFPPController as u16).unwrap()
            }
            PseudoPort::Local => bytes.write_u16::<BigEndian>(OfpPort::OFPPLocal as u16).unwrap(),
        }
    }
}

/// Actions associated with flows and packets.
#[derive(Copy, Clone)]
pub enum Action {
    Output(PseudoPort),
    SetDlVlan(Option<u16>),
    SetDlVlanPcp(u8),
    SetDlSrc([u8; 6]),
    SetDlDst([u8; 6]),
    SetNwSrc(u32),
    SetNwDst(u32),
    SetNwTos(u8),
    SetTpSrc(u16),
    SetTpDst(u16),
    Enqueue(PseudoPort, u32),
}

#[repr(packed)]
struct OfpActionHeader(u16, u16, [u8; 4]);

#[repr(packed)]
struct OfpActionOutput(u16, u16);
#[repr(packed)]
struct OfpActionVlanVId(u16, u16);
#[repr(packed)]
struct OfpActionVlanPcp(u8, [u8; 3]);
#[repr(packed)]
struct OfpActionStripVlan(u32);
#[repr(packed)]
struct OfpActionDlAddr([u8; 6], [u8; 6]);
#[repr(packed)]
struct OfpActionNwAddr(u32);
#[repr(packed)]
struct OfpActionTpPort(u16, u16);
#[repr(packed)]
struct OfpActionNwTos(u8, [u8; 3]);
#[repr(packed)]
struct OfpActionEnqueue(u16, [u8; 6], u32);

#[repr(u16)]
enum OfpActionType {
    OFPATOutput,
    OFPATSetVlanVId,
    OFPATSetVlanPCP,
    OFPATStripVlan,
    OFPATSetDlSrc,
    OFPATSetDlDst,
    OFPATSetNwSrc,
    OFPATSetNwDst,
    OFPATSetNwTos,
    OFPATSetTpSrc,
    OFPATSetTpDst,
    OFPATEnqueue,
}

impl Action {
    fn type_code(a: &Action) -> OfpActionType {
        match *a {
            Action::Output(_) => OfpActionType::OFPATOutput,
            Action::SetDlVlan(None) => OfpActionType::OFPATStripVlan,
            Action::SetDlVlan(Some(_)) => OfpActionType::OFPATSetVlanVId,
            Action::SetDlVlanPcp(_) => OfpActionType::OFPATSetVlanPCP,
            Action::SetDlSrc(_) => OfpActionType::OFPATSetDlSrc,
            Action::SetDlDst(_) => OfpActionType::OFPATSetDlDst,
            Action::SetNwSrc(_) => OfpActionType::OFPATSetNwSrc,
            Action::SetNwDst(_) => OfpActionType::OFPATSetNwDst,
            Action::SetNwTos(_) => OfpActionType::OFPATSetNwTos,
            Action::SetTpSrc(_) => OfpActionType::OFPATSetTpSrc,
            Action::SetTpDst(_) => OfpActionType::OFPATSetTpDst,
            Action::Enqueue(_, _) => OfpActionType::OFPATEnqueue,
        }
    }

    fn size_of(a: &Action) -> usize {
        let h = size_of::<OfpActionHeader>();
        let body = match *a {
            Action::Output(_) => size_of::<OfpActionOutput>(),
            Action::SetDlVlan(None) => size_of::<OfpActionStripVlan>(),
            Action::SetDlVlan(Some(_)) => size_of::<OfpActionVlanVId>(),
            Action::SetDlVlanPcp(_) => size_of::<OfpActionVlanPcp>(),
            Action::SetDlSrc(_) |
            Action::SetDlDst(_) => size_of::<OfpActionDlAddr>(),
            Action::SetNwSrc(_) |
            Action::SetNwDst(_) => size_of::<OfpActionNwAddr>(),
            Action::SetNwTos(_) => size_of::<OfpActionNwTos>(),
            Action::SetTpSrc(_) |
            Action::SetTpDst(_) => size_of::<OfpActionTpPort>(),
            Action::Enqueue(_, _) => size_of::<OfpActionEnqueue>(),
        };
        h + body
    }

    fn size_of_sequence(actions: &Vec<Action>) -> usize {
        actions.iter().fold(0, |acc, x| Action::size_of(x) + acc)
    }

    fn _parse(bytes: &mut Cursor<Vec<u8>>) -> (&mut Cursor<Vec<u8>>, Action) {
        let action_code = bytes.read_u16::<BigEndian>().unwrap();
        let _ = bytes.read_u16::<BigEndian>().unwrap();
        let action = match action_code {
            t if t == (OfpActionType::OFPATOutput as u16) => {
                let port_code = bytes.read_u16::<BigEndian>().unwrap();
                let len = bytes.read_u16::<BigEndian>().unwrap();
                Action::Output(PseudoPort::make(port_code, len as u64))
            }
            t if t == (OfpActionType::OFPATSetVlanVId as u16) => {
                let vid = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                if vid == 0xffff {
                    Action::SetDlVlan(None)
                } else {
                    Action::SetDlVlan(Some(vid))
                }
            }
            t if t == (OfpActionType::OFPATSetVlanPCP as u16) => {
                let pcp = bytes.read_u8().unwrap();
                bytes.consume(3);
                Action::SetDlVlanPcp(pcp)
            }
            t if t == (OfpActionType::OFPATStripVlan as u16) => {
                bytes.consume(4);
                Action::SetDlVlan(None)
            }
            t if t == (OfpActionType::OFPATSetDlSrc as u16) => {
                let mut dl_addr: [u8; 6] = [0; 6];
                for i in 0..6 {
                    dl_addr[i] = bytes.read_u8().unwrap();
                }
                bytes.consume(6);
                Action::SetDlSrc(dl_addr)
            }
            t if t == (OfpActionType::OFPATSetDlDst as u16) => {
                let mut dl_addr: [u8; 6] = [0; 6];
                for i in 0..6 {
                    dl_addr[i] = bytes.read_u8().unwrap();
                }
                bytes.consume(6);
                Action::SetDlDst(dl_addr)
            }
            t if t == (OfpActionType::OFPATSetNwSrc as u16) => {
                Action::SetNwSrc(bytes.read_u32::<BigEndian>().unwrap())
            }
            t if t == (OfpActionType::OFPATSetNwDst as u16) => {
                Action::SetNwDst(bytes.read_u32::<BigEndian>().unwrap())
            }
            t if t == (OfpActionType::OFPATSetNwTos as u16) => {
                let nw_tos = bytes.read_u8().unwrap();
                bytes.consume(3);
                Action::SetNwTos(nw_tos)
            }
            t if t == (OfpActionType::OFPATSetTpSrc as u16) => {
                let pt = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                Action::SetTpSrc(pt)
            }
            t if t == (OfpActionType::OFPATSetTpDst as u16) => {
                let pt = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                Action::SetTpDst(pt)
            }
            t if t == (OfpActionType::OFPATEnqueue as u16) => {
                let pt = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(6);
                let qid = bytes.read_u32::<BigEndian>().unwrap();
                Action::Enqueue(PseudoPort::make(pt, 0), qid)
            }
            t => panic!("Unrecognized OfpActionType {}", t),
        };
        (bytes, action)
    }

    fn parse_sequence(bytes: &mut Cursor<Vec<u8>>) -> Vec<Action> {
        if bytes.get_ref().is_empty() {
            vec![]
        } else {
            let (bytes_, action) = Action::_parse(bytes);
            let mut v = vec![action];
            v.append(&mut Action::parse_sequence(bytes_));
            v
        }
    }

    fn move_controller_last(acts: Vec<Action>) -> Vec<Action> {
        let (mut to_ctrl, mut not_to_ctrl): (Vec<Action>, Vec<Action>) = acts.into_iter()
            .partition(|act| match *act {
                Action::Output(PseudoPort::Controller(_)) => true,
                _ => false,
            });
        not_to_ctrl.append(&mut to_ctrl);
        not_to_ctrl
    }

    fn marshal(act: Action, bytes: &mut Vec<u8>) {
        bytes.write_u16::<BigEndian>(Action::type_code(&act) as u16).unwrap();
        bytes.write_u16::<BigEndian>(Action::size_of(&act) as u16).unwrap();
        bytes.write_u32::<BigEndian>(0).unwrap();
        match act {
            Action::Output(pp) => {
                PseudoPort::marshal(pp, bytes);
                bytes.write_u16::<BigEndian>(match pp {
                        PseudoPort::Controller(w) => w as u16,
                        _ => 0,
                    })
                    .unwrap()
            }
            Action::SetDlVlan(None) => bytes.write_u32::<BigEndian>(0xffff).unwrap(),
            Action::SetDlVlan(Some(vid)) => {
                bytes.write_u16::<BigEndian>(vid).unwrap();
                bytes.write_u16::<BigEndian>(0).unwrap();
            }
            Action::SetDlVlanPcp(n) => {
                bytes.write_u8(n).unwrap();
                for _ in 0..3 {
                    bytes.write_u8(0).unwrap();
                }
            }
            Action::SetDlSrc(mac) |
            Action::SetDlDst(mac) => {
                for i in 0..6 {
                    bytes.write_u8(mac[i]).unwrap();
                }
                for _ in 0..6 {
                    bytes.write_u8(0).unwrap();
                }
            }
            Action::SetNwSrc(addr) |
            Action::SetNwDst(addr) => bytes.write_u32::<BigEndian>(addr).unwrap(),
            Action::SetNwTos(n) => {
                bytes.write_u8(n).unwrap();
                for _ in 0..3 {
                    bytes.write_u8(0).unwrap();
                }
            }
            Action::SetTpSrc(pt) |
            Action::SetTpDst(pt) => {
                bytes.write_u16::<BigEndian>(pt).unwrap();
                bytes.write_u16::<BigEndian>(0).unwrap();
            }
            Action::Enqueue(pp, qid) => {
                PseudoPort::marshal(pp, bytes);
                for _ in 0..6 {
                    bytes.write_u8(0).unwrap();
                }
                bytes.write_u32::<BigEndian>(qid).unwrap();
            }
        }
    }
}

/// How long before a flow entry expires.
pub enum Timeout {
    Permanent,
    ExpiresAfter(u16),
}

impl Timeout {
    fn of_int(tm: u16) -> Timeout {
        match tm {
            0 => Timeout::Permanent,
            d => Timeout::ExpiresAfter(d),
        }
    }

    fn to_int(tm: Timeout) -> u16 {
        match tm {
            Timeout::Permanent => 0,
            Timeout::ExpiresAfter(d) => d,
        }
    }
}

/// Capabilities supported by the datapath.
pub struct Capabilities {
    pub flow_stats: bool,
    pub table_stats: bool,
    pub port_stats: bool,
    pub stp: bool,
    pub ip_reasm: bool,
    pub queue_stats: bool,
    pub arp_match_ip: bool,
}

/// Actions supported by the datapath.
pub struct SupportedActions {
    pub output: bool,
    pub set_vlan_id: bool,
    pub set_vlan_pcp: bool,
    pub strip_vlan: bool,
    pub set_dl_src: bool,
    pub set_dl_dst: bool,
    pub set_nw_src: bool,
    pub set_nw_dst: bool,
    pub set_nw_tos: bool,
    pub set_tp_src: bool,
    pub set_tp_dst: bool,
    pub enqueue: bool,
    pub vendor: bool,
}

/// Switch features.
pub struct SwitchFeatures {
    pub datapath_id: u64,
    pub num_buffers: u32,
    pub num_tables: u8,
    pub supported_capabilities: Capabilities,
    pub supported_actions: SupportedActions,
    pub ports: Vec<PortDesc>,
}

#[repr(packed)]
struct OfpSwitchFeatures(u64, u32, u8, [u8; 3], u32, u32);

impl MessageType for SwitchFeatures {
    fn size_of(sf: &SwitchFeatures) -> usize {
        let pds: usize = sf.ports.iter().map(|pd| PortDesc::size_of(pd)).sum();
        size_of::<OfpSwitchFeatures>() + pds
    }

    fn parse(buf: &[u8]) -> SwitchFeatures {
        let mut bytes = Cursor::new(buf.to_vec());
        let datapath_id = bytes.read_u64::<BigEndian>().unwrap();
        let num_buffers = bytes.read_u32::<BigEndian>().unwrap();
        let num_tables = bytes.read_u8().unwrap();
        bytes.consume(3);
        let supported_capabilities = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            Capabilities {
                flow_stats: test_bit(0, d as u64),
                table_stats: test_bit(1, d as u64),
                port_stats: test_bit(2, d as u64),
                stp: test_bit(3, d as u64),
                ip_reasm: test_bit(5, d as u64),
                queue_stats: test_bit(6, d as u64),
                arp_match_ip: test_bit(7, d as u64),
            }
        };
        let supported_actions = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            SupportedActions {
                output: test_bit(0, d as u64),
                set_vlan_id: test_bit(1, d as u64),
                set_vlan_pcp: test_bit(2, d as u64),
                strip_vlan: test_bit(3, d as u64),
                set_dl_src: test_bit(4, d as u64),
                set_dl_dst: test_bit(5, d as u64),
                set_nw_src: test_bit(6, d as u64),
                set_nw_dst: test_bit(7, d as u64),
                set_nw_tos: test_bit(8, d as u64),
                set_tp_src: test_bit(9, d as u64),
                set_tp_dst: test_bit(10, d as u64),
                enqueue: test_bit(11, d as u64),
                vendor: test_bit(12, d as u64),
            }
        };
        let ports = {
            let mut v = vec![];
            let num_ports = bytes.clone().into_inner().len() / size_of::<OfpPhyPort>();
            for _ in 0..num_ports {
                v.push(PortDesc::parse(&mut bytes))
            }
            v
        };
        SwitchFeatures {
            datapath_id: datapath_id,
            num_buffers: num_buffers,
            num_tables: num_tables,
            supported_capabilities: supported_capabilities,
            supported_actions: supported_actions,
            ports: ports,
        }
    }

    fn marshal(_: SwitchFeatures, _: &mut Vec<u8>) {}
}

/// Type of modification to perform on a flow table.
#[repr(u16)]
pub enum FlowModCmd {
    AddFlow,
    ModFlow,
    ModStrictFlow,
    DeleteFlow,
    DeleteStrictFlow,
}

/// Represents modifications to a flow table from the controller.
pub struct FlowMod {
    pub command: FlowModCmd,
    pub pattern: Pattern,
    pub priority: u16,
    pub actions: Vec<Action>,
    pub cookie: u64,
    pub idle_timeout: Timeout,
    pub hard_timeout: Timeout,
    pub notify_when_removed: bool,
    pub apply_to_packet: Option<u32>,
    pub out_port: Option<PseudoPort>,
    pub check_overlap: bool,
}

#[repr(packed)]
struct OfpFlowMod(u64, u16, u16, u16, u16, u32, u16, u16);

impl FlowMod {
    fn flags_to_int(check_overlap: bool, notify_when_removed: bool) -> u16 {
        (if check_overlap { 1 << 1 } else { 0 }) | (if notify_when_removed { 1 << 0 } else { 0 })
    }

    fn check_overlap_of_flags(flags: u16) -> bool {
        2 & flags != 0
    }

    fn notify_when_removed_of_flags(flags: u16) -> bool {
        1 & flags != 0
    }
}

impl MessageType for FlowMod {
    fn size_of(msg: &FlowMod) -> usize {
        Pattern::size_of(&msg.pattern) + size_of::<OfpFlowMod>() +
        Action::size_of_sequence(&msg.actions)
    }

    fn parse(buf: &[u8]) -> FlowMod {
        let mut bytes = Cursor::new(buf.to_vec());
        let pattern = Pattern::parse(&mut bytes);
        let cookie = bytes.read_u64::<BigEndian>().unwrap();
        let command = unsafe { transmute(bytes.read_u16::<BigEndian>().unwrap()) };
        let idle = Timeout::of_int(bytes.read_u16::<BigEndian>().unwrap());
        let hard = Timeout::of_int(bytes.read_u16::<BigEndian>().unwrap());
        let prio = bytes.read_u16::<BigEndian>().unwrap();
        let buffer_id = bytes.read_i32::<BigEndian>().unwrap();
        let out_port = PseudoPort::of_int(bytes.read_u16::<BigEndian>().unwrap());
        let flags = bytes.read_u16::<BigEndian>().unwrap();
        let actions = Action::parse_sequence(&mut bytes);
        FlowMod {
            command: command,
            pattern: pattern,
            priority: prio,
            actions: actions,
            cookie: cookie,
            idle_timeout: idle,
            hard_timeout: hard,
            notify_when_removed: FlowMod::notify_when_removed_of_flags(flags),
            apply_to_packet: {
                match buffer_id {
                    -1 => None,
                    n => Some(n as u32),
                }
            },
            out_port: out_port,
            check_overlap: FlowMod::check_overlap_of_flags(flags),
        }
    }

    fn marshal(fm: FlowMod, bytes: &mut Vec<u8>) {
        Pattern::marshal(fm.pattern, bytes);
        bytes.write_u64::<BigEndian>(fm.cookie).unwrap();
        bytes.write_u16::<BigEndian>(fm.command as u16).unwrap();
        bytes.write_u16::<BigEndian>(Timeout::to_int(fm.idle_timeout)).unwrap();
        bytes.write_u16::<BigEndian>(Timeout::to_int(fm.hard_timeout)).unwrap();
        bytes.write_u16::<BigEndian>(fm.priority).unwrap();
        bytes.write_i32::<BigEndian>(match fm.apply_to_packet {
                None => -1,
                Some(buf_id) => buf_id as i32,
            })
            .unwrap();
        match fm.out_port {
            None => bytes.write_u16::<BigEndian>(OfpPort::OFPPNone as u16).unwrap(),
            Some(x) => PseudoPort::marshal(x, bytes),
        }
        bytes.write_u16::<BigEndian>(FlowMod::flags_to_int(fm.check_overlap,
                                                          fm.notify_when_removed))
            .unwrap();
        for act in Action::move_controller_last(fm.actions) {
            match act {
                Action::Output(PseudoPort::Table) => {
                    panic!("OFPPTable not allowed in installed flow.")
                }
                _ => (),
            }
            Action::marshal(act, bytes)
        }
    }
}

/// The data associated with a packet received by the controller.
#[derive(Debug)]
pub enum Payload {
    Buffered(u32, Vec<u8>),
    NotBuffered(Vec<u8>),
}

impl Payload {
    pub fn size_of(payload: &Payload) -> usize {
        match *payload {
            Payload::Buffered(_, ref buf) |
            Payload::NotBuffered(ref buf) => buf.len(),
        }
    }

    fn marshal(payload: Payload, bytes: &mut Vec<u8>) {
        match payload {
            Payload::Buffered(_, buf) |
            Payload::NotBuffered(buf) => bytes.write_all(&buf).unwrap(),
        }
    }
}

/// The reason a packet arrives at the controller.
#[repr(u8)]
#[derive(Debug)]
pub enum PacketInReason {
    NoMatch,
    ExplicitSend,
}


/// Represents packets received by the datapath and sent to the controller.
#[derive(Debug)]
pub struct PacketIn {
    pub input_payload: Payload,
    pub total_len: u16,
    pub port: u16,
    pub reason: PacketInReason,
}

#[repr(packed)]
struct OfpPacketIn(i32, u16, u16, u8, u8);

impl MessageType for PacketIn {
    fn size_of(pi: &PacketIn) -> usize {
        size_of::<OfpPacketIn>() + Payload::size_of(&pi.input_payload)
    }

    fn parse(buf: &[u8]) -> PacketIn {
        let mut bytes = Cursor::new(buf.to_vec());
        let buf_id = match bytes.read_i32::<BigEndian>().unwrap() {
            -1 => None,
            n => Some(n),
        };
        let total_len = bytes.read_u16::<BigEndian>().unwrap();
        let port = bytes.read_u16::<BigEndian>().unwrap();
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        let pk = bytes;
        let payload = match buf_id {
            None => Payload::NotBuffered(pk.into_inner()),
            Some(n) => Payload::Buffered(n as u32, pk.into_inner()),
        };
        PacketIn {
            input_payload: payload,
            total_len: total_len,
            port: port,
            reason: reason,
        }
    }

    fn marshal(_: PacketIn, _: &mut Vec<u8>) {}
}

/// Represents packets sent from the controller.
pub struct PacketOut {
    pub output_payload: Payload,
    pub port_id: Option<u16>,
    pub apply_actions: Vec<Action>,
}

#[repr(packed)]
struct OfpPacketOut(u32, u16, u16);

impl MessageType for PacketOut {
    fn size_of(po: &PacketOut) -> usize {
        size_of::<OfpPacketOut>() + Action::size_of_sequence(&po.apply_actions) +
        Payload::size_of(&po.output_payload)
    }

    fn parse(buf: &[u8]) -> PacketOut {
        let mut bytes = Cursor::new(buf.to_vec());
        let buf_id = match bytes.read_i32::<BigEndian>().unwrap() {
            -1 => None,
            n => Some(n),
        };
        let in_port = bytes.read_u16::<BigEndian>().unwrap();
        let actions_len = bytes.read_u16::<BigEndian>().unwrap();
        let mut actions_buf = vec![0; actions_len as usize];
        bytes.read_exact(&mut actions_buf).unwrap();
        let mut actions_bytes = Cursor::new(actions_buf);
        let actions = Action::parse_sequence(&mut actions_bytes);
        PacketOut {
            output_payload: match buf_id {
                None => Payload::NotBuffered(bytes.into_inner()),
                Some(n) => Payload::Buffered(n as u32, bytes.into_inner()),
            },
            port_id: {
                if in_port == OfpPort::OFPPNone as u16 {
                    None
                } else {
                    Some(in_port)
                }
            },
            apply_actions: actions,
        }
    }

    fn marshal(po: PacketOut, bytes: &mut Vec<u8>) {
        bytes.write_i32::<BigEndian>(match po.output_payload {
                Payload::Buffered(n, _) => n as i32,
                Payload::NotBuffered(_) => -1,
            })
            .unwrap();
        match po.port_id {
            Some(id) => PseudoPort::marshal(PseudoPort::PhysicalPort(id), bytes),
            None => bytes.write_u16::<BigEndian>(OfpPort::OFPPNone as u16).unwrap(),
        }
        bytes.write_u16::<BigEndian>(Action::size_of_sequence(&po.apply_actions) as u16).unwrap();
        for act in Action::move_controller_last(po.apply_actions) {
            Action::marshal(act, bytes);
        }
        Payload::marshal(po.output_payload, bytes)
    }
}

/// Reason a flow was removed from a switch
#[repr(u8)]
pub enum FlowRemovedReason {
    IdleTimeout,
    HardTimeout,
    Delete,
}

/// Flow removed (datapath -> controller)
pub struct FlowRemoved {
    pub pattern: Pattern,
    pub cookie: i64,
    pub priority: u16,
    pub reason: FlowRemovedReason,
    pub duration_sec: u32,
    pub duration_nsec: u32,
    pub idle_timeout: Timeout,
    pub packet_count: u64,
    pub byte_count: u64,
}

#[repr(packed)]
struct OfpFlowRemoved(u64, u16, u8, u8, u32, u32, u16, u16, u64, u64);

impl MessageType for FlowRemoved {
    fn size_of(f: &FlowRemoved) -> usize {
        Pattern::size_of(&f.pattern) + size_of::<OfpFlowRemoved>()
    }

    fn parse(buf: &[u8]) -> FlowRemoved {
        let mut bytes = Cursor::new(buf.to_vec());
        let pattern = Pattern::parse(&mut bytes);
        let cookie = bytes.read_i64::<BigEndian>().unwrap();
        let priority = bytes.read_u16::<BigEndian>().unwrap();
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        bytes.consume(1);
        let duration_sec = bytes.read_u32::<BigEndian>().unwrap();
        let duration_nsec = bytes.read_u32::<BigEndian>().unwrap();
        let idle = Timeout::of_int(bytes.read_u16::<BigEndian>().unwrap());
        bytes.consume(2);
        let packet_count = bytes.read_u64::<BigEndian>().unwrap();
        let byte_count = bytes.read_u64::<BigEndian>().unwrap();
        FlowRemoved {
            pattern: pattern,
            cookie: cookie,
            priority: priority,
            reason: reason,
            duration_sec: duration_sec,
            duration_nsec: duration_nsec,
            idle_timeout: idle,
            packet_count: packet_count,
            byte_count: byte_count,
        }
    }

    fn marshal(f: FlowRemoved, bytes: &mut Vec<u8>) {
        Pattern::marshal(f.pattern, bytes);
        bytes.write_i64::<BigEndian>(f.cookie).unwrap();
        bytes.write_u16::<BigEndian>(f.priority).unwrap();
        bytes.write_u8(f.reason as u8).unwrap();
        bytes.write_u8(0).unwrap();
        bytes.write_u32::<BigEndian>(f.duration_sec).unwrap();
        bytes.write_u32::<BigEndian>(f.duration_nsec).unwrap();
        bytes.write_u16::<BigEndian>(Timeout::to_int(f.idle_timeout)).unwrap();
        bytes.write_u64::<BigEndian>(f.packet_count).unwrap();
        bytes.write_u64::<BigEndian>(f.byte_count).unwrap();
    }
}

/// STP state of a port.
#[repr(u8)]
pub enum StpState {
    Listen,
    Learn,
    Forward,
    Block,
}

/// Current state of a physical port. Not configurable by the controller.
pub struct PortState {
    pub down: bool,
    pub stp_state: StpState,
}

/// Features of physical ports available in a datapath.
pub struct PortFeatures {
    pub f_10mbhd: bool,
    pub f_10mbfd: bool,
    pub f_100mbhd: bool,
    pub f_100mbfd: bool,
    pub f_1gbhd: bool,
    pub f_1gbfd: bool,
    pub f_10gbfd: bool,
    pub copper: bool,
    pub fiber: bool,
    pub autoneg: bool,
    pub pause: bool,
    pub pause_asym: bool,
}

impl PortFeatures {
    fn of_int(d: u32) -> PortFeatures {
        PortFeatures {
            f_10mbhd: test_bit(0, d as u64),
            f_10mbfd: test_bit(1, d as u64),
            f_100mbhd: test_bit(2, d as u64),
            f_100mbfd: test_bit(3, d as u64),
            f_1gbhd: test_bit(4, d as u64),
            f_1gbfd: test_bit(5, d as u64),
            f_10gbfd: test_bit(6, d as u64),
            copper: test_bit(7, d as u64),
            fiber: test_bit(8, d as u64),
            autoneg: test_bit(9, d as u64),
            pause: test_bit(10, d as u64),
            pause_asym: test_bit(11, d as u64),
        }
    }
}

/// Flags to indicate behavior of the physical port.
///
/// These flags are used both to describe the current configuration of a physical port,
/// and to configure a port's behavior.
pub struct PortConfig {
    pub down: bool,
    pub no_stp: bool,
    pub no_recv: bool,
    pub no_recv_stp: bool,
    pub no_flood: bool,
    pub no_fwd: bool,
    pub no_packet_in: bool,
}

/// Description of a physical port.
pub struct PortDesc {
    pub port_no: u16,
    pub hw_addr: i64,
    pub name: String,
    pub config: PortConfig,
    pub state: PortState,
    pub curr: PortFeatures,
    pub advertised: PortFeatures,
    pub supported: PortFeatures,
    pub peer: PortFeatures,
}

#[repr(packed)]
struct OfpPhyPort(u16, [u8; 6], [u8; 16], u32, u32, u32, u32, u32, u32);

impl PortDesc {
    fn size_of(_: &PortDesc) -> usize {
        size_of::<OfpPhyPort>()
    }

    fn parse(bytes: &mut Cursor<Vec<u8>>) -> PortDesc {
        let port_no = bytes.read_u16::<BigEndian>().unwrap();
        let hw_addr = {
            let mut arr: [u8; 8] = [0; 8];
            for i in 2..8 {
                arr[i] = bytes.read_u8().unwrap();
            }
            unsafe { transmute(arr) }
        };
        let name = {
            let mut arr: [u8; 16] = [0; 16];
            for i in 0..16 {
                arr[i] = bytes.read_u8().unwrap();
            }
            String::from_utf8(arr.to_vec()).unwrap()
        };
        let config = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            PortConfig {
                down: test_bit(0, d as u64),
                no_stp: test_bit(1, d as u64),
                no_recv: test_bit(2, d as u64),
                no_recv_stp: test_bit(3, d as u64),
                no_flood: test_bit(4, d as u64),
                no_fwd: test_bit(5, d as u64),
                no_packet_in: test_bit(6, d as u64),
            }
        };
        let state = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            PortState {
                down: test_bit(0, d as u64),
                stp_state: {
                    let mask: u32 = 3 << 8;
                    let d_masked = d & mask;
                    if d_masked == (StpState::Listen as u32) << 8 {
                        StpState::Listen
                    } else if d_masked == (StpState::Learn as u32) << 8 {
                        StpState::Learn
                    } else if d_masked == (StpState::Forward as u32) << 8 {
                        StpState::Forward
                    } else if d_masked == (StpState::Block as u32) << 8 {
                        StpState::Block
                    } else {
                        panic!("Unexpected ofp_port_state for STP: {}", d_masked)
                    }
                },
            }
        };
        let curr = PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let advertised = PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let supported = PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let peer = PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap());
        PortDesc {
            port_no: port_no,
            hw_addr: hw_addr,
            name: name,
            config: config,
            state: state,
            curr: curr,
            advertised: advertised,
            supported: supported,
            peer: peer,
        }
    }
}

/// What changed about a physical port.
#[repr(u8)]
pub enum PortReason {
    PortAdd,
    PortDelete,
    PortModify,
}

/// A physical port has changed in the datapath.
pub struct PortStatus {
    pub reason: PortReason,
    pub desc: PortDesc,
}

impl MessageType for PortStatus {
    fn size_of(_: &PortStatus) -> usize {
        size_of::<PortReason>() + size_of::<OfpPhyPort>()
    }

    fn parse(buf: &[u8]) -> PortStatus {
        let mut bytes = Cursor::new(buf.to_vec());
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        bytes.consume(7);
        let desc = PortDesc::parse(&mut bytes);
        PortStatus {
            reason: reason,
            desc: desc,
        }
    }

    fn marshal(_: PortStatus, _: &mut Vec<u8>) {}
}

/// Reason Hello failed.
#[repr(u16)]
#[derive(Debug)]
pub enum HelloFailed {
    Incompatible,
    EPerm,
}

/// Reason the controller made a bad request to a switch.
#[repr(u16)]
#[derive(Debug)]
pub enum BadRequest {
    BadVersion,
    BadType,
    BadStat,
    BadVendor,
    BadSubType,
    EPerm,
    BadLen,
    BufferEmpty,
    BufferUnknown,
}

/// Reason the controller action failed.
#[repr(u16)]
#[derive(Debug)]
pub enum BadAction {
    BadType,
    BadLen,
    BadVendor,
    BadVendorType,
    BadOutPort,
    BadArgument,
    EPerm,
    TooMany,
    BadQueue,
}

/// Reason a FlowMod from the controller failed.
#[repr(u16)]
#[derive(Debug)]
pub enum FlowModFailed {
    AllTablesFull,
    Overlap,
    EPerm,
    BadEmergTimeout,
    BadCommand,
    Unsupported,
}

/// Reason a PortMod from the controller failed.
#[repr(u16)]
#[derive(Debug)]
pub enum PortModFailed {
    BadPort,
    BadHwAddr,
}

/// Reason a queue operation from the controller failed.
#[repr(u16)]
#[derive(Debug)]
pub enum QueueOpFailed {
    BadPort,
    BadQueue,
    EPerm,
}

/// High-level type of OpenFlow error
#[derive(Debug)]
pub enum ErrorType {
    HelloFailed(HelloFailed),
    BadRequest(BadRequest),
    BadAction(BadAction),
    FlowModFailed(FlowModFailed),
    PortModFailed(PortModFailed),
    QueueOpFailed(QueueOpFailed),
}

/// Error message (datapath -> controller)
#[derive(Debug)]
pub enum Error {
    Error(ErrorType, Vec<u8>),
}

#[repr(packed)]
struct OfpErrorMsg(u16, u16);

impl MessageType for Error {
    fn size_of(err: &Error) -> usize {
        match *err {
            Error::Error(_, ref body) => size_of::<OfpErrorMsg>() + body.len(),
        }
    }

    fn parse(buf: &[u8]) -> Error {
        let mut bytes = Cursor::new(buf.to_vec());
        let error_type = bytes.read_u16::<BigEndian>().unwrap();
        let error_code = bytes.read_u16::<BigEndian>().unwrap();
        let code = match error_type {
            0 => ErrorType::HelloFailed(unsafe { transmute(error_code) }),
            1 => ErrorType::BadRequest(unsafe { transmute(error_code) }),
            2 => ErrorType::BadAction(unsafe { transmute(error_code) }),
            3 => ErrorType::FlowModFailed(unsafe { transmute(error_code) }),
            4 => ErrorType::PortModFailed(unsafe { transmute(error_code) }),
            5 => ErrorType::QueueOpFailed(unsafe { transmute(error_code) }),
            _ => panic!("bad ErrorType in Error {}", error_type),
        };
        Error::Error(code, bytes.into_inner())
    }

    fn marshal(_: Error, _: &mut Vec<u8>) {}
}

/// Encapsulates handling of messages implementing `MessageType` trait.
pub mod message {
    use super::*;
    use std::io::Write;
    use ofp_header::OfpHeader;
    use ofp_message::OfpMessage;
    use packet::Packet;

    /// Abstractions of OpenFlow 1.0 messages mapping to message codes.
    pub enum Message {
        Hello,
        Error(Error),
        EchoRequest(Vec<u8>),
        EchoReply(Vec<u8>),
        FeaturesReq,
        FeaturesReply(SwitchFeatures),
        FlowMod(FlowMod),
        PacketIn(PacketIn),
        FlowRemoved(FlowRemoved),
        PortStatus(PortStatus),
        PacketOut(PacketOut),
        BarrierRequest,
        BarrierReply,
    }

    impl Message {
        /// Map `Message` to associated OpenFlow message type code `MsgCode`.
        fn msg_code_of_message(msg: &Message) -> MsgCode {
            match *msg {
                Message::Hello => MsgCode::Hello,
                Message::Error(_) => MsgCode::Error,
                Message::EchoRequest(_) => MsgCode::EchoReq,
                Message::EchoReply(_) => MsgCode::EchoResp,
                Message::FeaturesReq => MsgCode::FeaturesReq,
                Message::FeaturesReply(_) => MsgCode::FeaturesResp,
                Message::FlowMod(_) => MsgCode::FlowMod,
                Message::PacketIn(_) => MsgCode::PacketIn,
                Message::FlowRemoved(_) => MsgCode::FlowRemoved,
                Message::PortStatus(_) => MsgCode::PortStatus,
                Message::PacketOut(_) => MsgCode::PacketOut,
                Message::BarrierRequest => MsgCode::BarrierReq,
                Message::BarrierReply => MsgCode::BarrierResp,
            }
        }

        /// Marshal the OpenFlow message `msg`.
        fn marshal_body(msg: Message, bytes: &mut Vec<u8>) {
            match msg {
                Message::Hello => (),
                Message::Error(buf) => Error::marshal(buf, bytes),
                Message::EchoReply(buf) => bytes.write_all(&buf).unwrap(),
                Message::EchoRequest(buf) => bytes.write_all(&buf).unwrap(),
                Message::FeaturesReq => (),
                Message::FlowMod(flow_mod) => FlowMod::marshal(flow_mod, bytes),
                Message::PacketIn(packet_in) => PacketIn::marshal(packet_in, bytes),
                Message::FlowRemoved(flow) => FlowRemoved::marshal(flow, bytes),
                Message::PortStatus(sts) => PortStatus::marshal(sts, bytes),
                Message::PacketOut(po) => PacketOut::marshal(po, bytes),
                Message::BarrierRequest | Message::BarrierReply => (),
                _ => (),
            }
        }
    }

    impl OfpMessage for Message {
        fn size_of(msg: &Message) -> usize {
            match *msg {
                Message::Hello => OfpHeader::size(),
                Message::Error(ref err) => Error::size_of(err),
                Message::EchoRequest(ref buf) => OfpHeader::size() + buf.len(),
                Message::EchoReply(ref buf) => OfpHeader::size() + buf.len(),
                Message::FeaturesReq => OfpHeader::size(),
                Message::FlowMod(ref flow_mod) => OfpHeader::size() + FlowMod::size_of(flow_mod),
                Message::PacketIn(ref packet_in) => {
                    OfpHeader::size() + PacketIn::size_of(packet_in)
                }
                Message::FlowRemoved(ref flow) => OfpHeader::size() + FlowRemoved::size_of(flow),
                Message::PortStatus(ref ps) => OfpHeader::size() + PortStatus::size_of(ps),
                Message::PacketOut(ref po) => OfpHeader::size() + PacketOut::size_of(po),
                Message::BarrierRequest | Message::BarrierReply => OfpHeader::size(),
                _ => 0,
            }
        }

        fn header_of(xid: u32, msg: &Message) -> OfpHeader {
            let sizeof_buf = Self::size_of(&msg);
            OfpHeader::new(0x01,
                           Self::msg_code_of_message(msg) as u8,
                           sizeof_buf as u16,
                           xid)
        }

        fn marshal(xid: u32, msg: Message) -> Vec<u8> {
            let hdr = Self::header_of(xid, &msg);
            let mut bytes = vec![];
            OfpHeader::marshal(&mut bytes, hdr);
            Message::marshal_body(msg, &mut bytes);
            bytes
        }

        fn parse(header: &OfpHeader, buf: &[u8]) -> (u32, Message) {
            let typ = header.type_code();
            let msg = match typ {
                MsgCode::Hello => {
                    println!("Hello!");
                    Message::Hello
                }
                MsgCode::Error => {
                    println!("Error");
                    Message::Error(Error::parse(buf))
                }
                MsgCode::EchoReq => Message::EchoRequest(buf.to_vec()),
                MsgCode::EchoResp => Message::EchoReply(buf.to_vec()),
                MsgCode::FeaturesResp => {
                    println!("FeaturesResp");
                    Message::FeaturesReply(SwitchFeatures::parse(buf))
                }
                MsgCode::FlowMod => {
                    println!("FlowMod");
                    Message::FlowMod(FlowMod::parse(buf))
                }
                MsgCode::PacketIn => {
                    println!("PacketIn");
                    Message::PacketIn(PacketIn::parse(buf))
                }
                MsgCode::FlowRemoved => {
                    println!("FlowRemoved");
                    Message::FlowRemoved(FlowRemoved::parse(buf))
                }
                MsgCode::PortStatus => {
                    println!("PortStatus");
                    Message::PortStatus(PortStatus::parse(buf))
                }
                MsgCode::PacketOut => {
                    println!("PacketOut");
                    Message::PacketOut(PacketOut::parse(buf))
                }
                MsgCode::BarrierReq => Message::BarrierRequest,
                MsgCode::BarrierResp => Message::BarrierReply,
                code => panic!("Unexpected message type {:?}", code),
            };
            (header.xid(), msg)
        }
    }

    /// Return a `FlowMod` adding a flow parameterized by the given `priority`, `pattern`,
    /// and `actions`.
    pub fn add_flow(prio: u16, pattern: Pattern, actions: Vec<Action>) -> FlowMod {
        FlowMod {
            command: FlowModCmd::AddFlow,
            pattern: pattern,
            priority: prio,
            actions: actions,
            cookie: 0,
            idle_timeout: Timeout::Permanent,
            hard_timeout: Timeout::Permanent,
            notify_when_removed: false,
            out_port: None,
            apply_to_packet: None,
            check_overlap: false,
        }
    }

    /// Parse a payload buffer into a network level packet.
    pub fn parse_payload(p: &Payload) -> Packet {
        match *p {
            Payload::Buffered(_, ref b) |
            Payload::NotBuffered(ref b) => Packet::parse(&b),
        }
    }
}
