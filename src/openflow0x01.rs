use std::io::{BufRead, Cursor};
use std::mem::{size_of, transmute};

use byteorder::{BigEndian, ReadBytesExt};

fn test_bit(bit: u64, x: u64) -> bool {
    (x >> bit) & 1 == 1
}

pub struct Pattern {}

#[repr(packed)]
struct OfpMatch(u32, u16, [u8; 6], [u8; 6], u16, u8, u8, u16, u8, u8, u16, u32, u32, u16, u16);

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

#[derive(Copy, Clone)]
pub enum Action {
    Output(PseudoPort),
}

#[repr(packed)]
struct OfpActionHeader(u16, u16);

#[repr(packed)]
struct OfpActionOutput(u16, u16);

impl Action {
    fn size_of(a: &Action) -> usize {
        let h = size_of::<OfpActionHeader>();
        let body = match *a {
            Action::Output(_) => size_of::<OfpActionOutput>(),
        };
        h + body
    }

    pub fn size_of_sequence(actions: Vec<Action>) -> usize {
        actions.iter().fold(0, |acc, x| Action::size_of(x) + acc)
    }
}

pub enum Timeout {
    Permanent,
    ExpiresAfter(u16),
}

#[repr(u8)]
#[derive(Copy, Clone)]
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

pub struct Capabilities {
    pub flow_stats: bool,
    pub table_stats: bool,
    pub port_stats: bool,
    pub stp: bool,
    pub ip_reasm: bool,
    pub queue_stats: bool,
    pub arp_match_ip: bool,
}

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

impl SwitchFeatures {
    pub fn parse(buf: &[u8], buf_len: usize) -> SwitchFeatures {
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
            let num_ports = (buf_len - size_of::<OfpSwitchFeatures>()) / size_of::<OfpPhyPort>();
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
}

pub enum FlowModCmd {
    AddFlow,
    ModFlow,
    ModStrictFlow,
    DeleteFlow,
    DeleteStrictFlow,
}

pub struct FlowMod {
    pub command: FlowModCmd,
    pub pattern: u8,
    pub priority: u16,
    pub actions: Vec<Action>,
    pub cookie: i64,
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
    pub fn size_of(msg: &FlowMod) -> usize {
        size_of::<OfpMatch>() + size_of::<OfpFlowMod>() +
        Action::size_of_sequence(msg.actions.clone())
    }

    pub fn marshal(_: FlowMod, _: &mut Vec<u8>) {}
}

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
}

#[repr(u8)]
pub enum PacketInReason {
    NoMatch,
    ExplicitSend,
}

pub struct PacketIn {
    pub input_payload: Payload,
    pub total_len: u16,
    pub port: u16,
    pub reason: PacketInReason,
}

#[repr(packed)]
struct OfpPacketIn(i32, u16, u16, u8, u8);

impl PacketIn {
    pub fn size_of(pi: &PacketIn) -> usize {
        size_of::<OfpPacketIn>() + Payload::size_of(&pi.input_payload)
    }

    pub fn parse(buf: &[u8]) -> PacketIn {
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

    pub fn marshal(_: PacketIn, _: &mut Vec<u8>) {}
}

#[repr(u8)]
pub enum StpState {
    Listen,
    Learn,
    Forward,
    Block,
}

pub struct PortState {
    pub down: bool,
    pub stp_state: StpState,
}

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

pub struct PortConfig {
    pub down: bool,
    pub no_stp: bool,
    pub no_recv: bool,
    pub no_recv_stp: bool,
    pub no_flood: bool,
    pub no_fwd: bool,
    pub no_packet_in: bool,
}

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

#[repr(u8)]
pub enum PortReason {
    PortAdd,
    PortDelete,
    PortModify,
}

pub struct PortStatus {
    pub reason: PortReason,
    pub desc: PortDesc,
}

impl PortStatus {
    pub fn size_of() -> usize {
        size_of::<PortReason>() + size_of::<OfpPhyPort>()
    }

    pub fn parse(buf: &[u8]) -> PortStatus {
        let mut bytes = Cursor::new(buf.to_vec());
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        bytes.consume(7);
        let desc = PortDesc::parse(&mut bytes);
        PortStatus {
            reason: reason,
            desc: desc,
        }
    }

    pub fn marshal(_: PortStatus, _: &mut Vec<u8>) {}
}

pub mod message {
    use super::*;
    use byteorder::WriteBytesExt;
    use ofp_header::OfpHeader;

    pub enum Message {
        Hello,
        EchoRequest(Vec<u8>),
        EchoReply(Vec<u8>),
        FeaturesReq,
        FeaturesReply(SwitchFeatures),
        FlowMod(FlowMod),
        PacketIn(PacketIn),
        PortStatus(PortStatus),
    }

    impl Message {
        fn msg_code_of_message(msg: &Message) -> MsgCode {
            match *msg {
                Message::Hello => MsgCode::Hello,
                Message::EchoRequest(_) => MsgCode::EchoReq,
                Message::EchoReply(_) => MsgCode::EchoResp,
                Message::FeaturesReq => MsgCode::FeaturesReq,
                Message::FeaturesReply(_) => MsgCode::FeaturesResp,
                Message::FlowMod(_) => MsgCode::FlowMod,
                Message::PortStatus(_) => MsgCode::PortStatus,
                Message::PacketIn(_) => MsgCode::PacketIn,
                // _ => MsgCode::Hello
            }
        }

        fn size_of(msg: &Message) -> usize {
            match *msg {
                Message::Hello => OfpHeader::size(),
                Message::EchoRequest(ref buf) => OfpHeader::size() + buf.len(),
                Message::EchoReply(ref buf) => OfpHeader::size() + buf.len(),
                Message::FeaturesReq => OfpHeader::size(),
                Message::FlowMod(ref flow_mod) => OfpHeader::size() + FlowMod::size_of(flow_mod),
                Message::PacketIn(ref packet_in) => {
                    OfpHeader::size() + PacketIn::size_of(packet_in)
                }
                Message::PortStatus(_) => OfpHeader::size() + PortStatus::size_of(),
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

        fn marshal_body(msg: Message, bytes: &mut Vec<u8>) {
            match msg {
                Message::Hello => (),
                Message::EchoReply(buf) => {
                    for b in buf {
                        bytes.write_u8(b).unwrap();
                    }
                }
                Message::EchoRequest(buf) => {
                    for b in buf {
                        bytes.write_u8(b).unwrap();
                    }
                }
                Message::FeaturesReq => (),
                Message::FlowMod(flow_mod) => FlowMod::marshal(flow_mod, bytes),
                Message::PacketIn(packet_in) => PacketIn::marshal(packet_in, bytes),
                Message::PortStatus(sts) => PortStatus::marshal(sts, bytes),
                _ => (),
            }
        }

        pub fn marshal(xid: u32, msg: Message) -> Vec<u8> {
            let hdr = Self::header_of(xid, &msg);
            let mut bytes = vec![];
            OfpHeader::marshal(&mut bytes, hdr);
            Message::marshal_body(msg, &mut bytes);
            bytes
        }

        pub fn parse(header: &OfpHeader, buf: &[u8], buf_len: usize) -> (u32, Message) {
            let typ = header.type_code();
            let msg = match typ {
                MsgCode::Hello => {
                    println!("Hello!");
                    Message::Hello
                }
                MsgCode::EchoReq => Message::EchoRequest(buf.to_vec()),
                MsgCode::EchoResp => Message::EchoReply(buf.to_vec()),
                MsgCode::FeaturesResp => {
                    println!("FeaturesResp");
                    Message::FeaturesReply(SwitchFeatures::parse(buf, buf_len))
                }
                MsgCode::PacketIn => {
                    println!("PacketIn");
                    Message::PacketIn(PacketIn::parse(buf))
                }
                MsgCode::PortStatus => {
                    println!("PortStatus");
                    Message::PortStatus(PortStatus::parse(buf))
                }
                t => {
                    println!("{}", t as u8);
                    Message::Hello
                }
            };
            (header.xid(), msg)
        }
    }

    pub fn add_flow(prio: u16, pattern: u8, actions: Vec<Action>) -> FlowMod {
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
}
