use std::io::Cursor;
use std::mem::{size_of, transmute};

use byteorder::{BigEndian, ReadBytesExt};

fn test_bit(bit: u64, x: u64) -> bool {
    (x >> bit) & 1 == 1
}

pub struct Pattern {}

struct OfpMatch {
    wildcards: u32,
    in_port: u16,
    dl_src: [u8; 6],
    dl_dst: [u8; 6],
    dl_vlan: u16,
    dl_vlan_pcp: u8,
    pad1: u8,
    dl_type: u16,
    nw_tos: u8,
    nw_proto: u8,
    pad2: u16,
    nw_src: u32,
    nw_dst: u32,
    tp_src: u16,
    tp_dst: u16,
}

#[derive(Copy, Clone)]
pub enum PseudoPort {
    PhysicalPort(u16),
    InPort,
    Table,
    Normal,
    Flood,
    AllPorts,
    Controller(u64),
    Local
}

#[derive(Copy, Clone)]
pub enum Action {
    Output(PseudoPort),
}

struct OfpActionHeader {
    typ: u16,
    len: u16
}

struct OfpActionOutput {
    port: u16,
    max_len: u16
}

impl Action {
    fn size_of(a: &Action) -> usize {
        let h = size_of::<OfpActionHeader>();
        let body = match *a {
            Action::Output(_) => size_of::<OfpActionOutput>()
        };
        h + body
    }

    pub fn size_of_sequence(actions: Vec<Action>) -> usize {
        actions.iter().fold(0, |acc, x| Action::size_of(x) + acc)
    }
}

pub enum Timeout {
    Permanent,
    ExpiresAfter(u16)
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
    pub group_stats: bool,
    pub ip_reasm: bool,
    pub queue_stats: bool,
    pub port_blocked: bool,
}

pub struct SwitchFeatures {
    pub datapath_id: u64,
    pub num_buffers: u32,
    pub num_tables: u8,
    pub aux_id: u8,
    pub supported_capabilities: Capabilities,
}

impl SwitchFeatures {
    pub fn parse(buf: &[u8]) -> SwitchFeatures {
        let mut bytes = Cursor::new(buf.to_vec());
        SwitchFeatures {
            datapath_id: bytes.read_u64::<BigEndian>().unwrap(),
            num_buffers: bytes.read_u32::<BigEndian>().unwrap(),
            num_tables: bytes.read_u8().unwrap(),
            aux_id: bytes.read_u8().unwrap(),
            supported_capabilities: Capabilities {
                flow_stats: bytes.read_u8().unwrap() != 0,
                table_stats: bytes.read_u8().unwrap() != 0,
                port_stats: bytes.read_u8().unwrap() != 0,
                group_stats: bytes.read_u8().unwrap() != 0,
                ip_reasm: bytes.read_u8().unwrap() != 0,
                queue_stats: bytes.read_u8().unwrap() != 0,
                port_blocked: bytes.read_u8().unwrap() != 0,
            }
        }
    }
}

pub enum FlowModCmd {
    AddFlow,
    ModFlow,
    ModStrictFlow,
    DeleteFlow,
    DeleteStrictFlow
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
    pub check_overlap: bool
}

struct OfpFlowMod {
    cookie: u64,
    command: u16,
    idle_timeout: u16,
    hard_timeout: u16,
    priority: u16,
    buffer_id: u32,
    out_port: u16,
    flags: u16
}

impl FlowMod {
    pub fn size_of(msg: &FlowMod) -> usize {
        size_of::<OfpMatch>() + size_of::<OfpFlowMod>() + Action::size_of_sequence(msg.actions.clone())
    }

    pub fn marshal(msg: FlowMod, bytes: &mut Vec<u8>) {
        
    }
}

#[repr(u8)]
pub enum StpState {
    Listen,
    Learn,
    Forward,
    Block
}

pub struct PortState {
    pub down: bool,
    pub stp_state: StpState
}

pub struct PortFeatures {
    pub f_10MBHD: bool,
    pub f_10MBFD: bool,
    pub f_100MBHD: bool,
    pub f_100MBFD: bool,
    pub f_1GBHD: bool,
    pub f_1GBFD: bool,
    pub f_10GBFD: bool,
    pub copper: bool,
    pub fiber: bool,
    pub autoneg: bool,
    pub pause: bool,
    pub pause_asym: bool
}

impl PortFeatures {
    fn of_int(d: u32) -> PortFeatures {
        PortFeatures {
            f_10MBHD: test_bit(0, d as u64),
            f_10MBFD: test_bit(1, d as u64),
            f_100MBHD: test_bit(2, d as u64),
            f_100MBFD: test_bit(3, d as u64),
            f_1GBHD: test_bit(4, d as u64),
            f_1GBFD: test_bit(5, d as u64),
            f_10GBFD: test_bit(6, d as u64),
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
    pub no_packet_in: bool
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

struct OfpPhyPort {
    port_no: u16,
    hw_addr: [u8; 6],
    name: [u8; 16],
    config: u32,
    state: u32,
    curr: u32,
    advertised: u32,
    supported: u32,
    peer: u32
}

#[repr(u8)]
pub enum PortReason {
    PortAdd,
    PortDelete,
    PortModify
}

pub struct PortStatus {
    pub reason: PortReason,
    pub desc: PortDesc
}

struct OfpPortStatus {
    reason: u8,
    pad: [u8; 7]
}

impl PortStatus {
    pub fn size_of() -> usize {
        size_of::<PortReason>() + size_of::<OfpPhyPort>()
    }

    pub fn parse(buf: &[u8]) -> PortStatus {
        let mut bytes = Cursor::new(buf.to_vec());
        PortStatus {
            reason: {
                let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
                // read through padding
                for _ in 0..7 { let _ = bytes.read_u8(); }
                reason
            },
            desc: PortDesc {
                port_no: bytes.read_u16::<BigEndian>().unwrap(),
                hw_addr: {
                    let mut arr: [u8; 8] = [0;8];
                    for i in 0..6 {
                        arr[i] = bytes.read_u8().unwrap();
                    }
                    unsafe { transmute(arr) }
                },
                name: {
                    let mut arr: [u8; 16] = [0; 16];
                    for i in 0..16 {
                        arr[i] = bytes.read_u8().unwrap();
                    }
                    String::from_utf8(arr.to_vec()).unwrap()
                },
                config: {
                    let d = bytes.read_u8().unwrap();
                    PortConfig {
                        down: test_bit(0, d as u64),
                        no_stp: test_bit(1, d as u64),
                        no_recv: test_bit(2, d as u64),
                        no_recv_stp: test_bit(3, d as u64),
                        no_flood: test_bit(4, d as u64),
                        no_fwd: test_bit(5, d as u64),
                        no_packet_in: test_bit(6, d as u64)
                    }
                },
                state: {
                    let d = bytes.read_u32::<BigEndian>().unwrap();
                    PortState {
                        down: test_bit(0, d as u64),
                        stp_state: {
                            let mask: u32 = 3 << 8;
                            let d_masked = d & mask;
                            if d_masked == (StpState::Listen as u32) << 8 { StpState::Listen }
                            else if d_masked == (StpState::Learn as u32) << 8 { StpState::Learn }
                            else if d_masked == (StpState::Forward as u32) << 8 { StpState::Forward }
                            else if d_masked == (StpState::Block as u32) << 8 { StpState::Block }
                            else { panic!("Unexpected ofp_port_state for STP: {}", d_masked) }
                        }
                    }
                },
                curr: PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap()),
                advertised: PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap()),
                supported: PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap()),
                peer: PortFeatures::of_int(bytes.read_u32::<BigEndian>().unwrap()),
            }
        }
    }

    pub fn marshal(sts: PortStatus, bytes: &mut Vec<u8>) {

    }
}

pub mod message {
    use super::*;
    use ofp_header::OfpHeader;

    pub enum Message {
        Hello,
        FeaturesReq,
        FeaturesReply(SwitchFeatures),
        FlowMod(FlowMod),
        PortStatus(PortStatus)
    }

    impl Message {
        fn msg_code_of_message(msg: &Message) -> MsgCode {
            match *msg {
                Message::Hello => MsgCode::Hello,
                Message::FeaturesReq => MsgCode::FeaturesReq,
                Message::FeaturesReply(_) => MsgCode::FeaturesResp,
                Message::FlowMod(_) => MsgCode::FlowMod,
                Message::PortStatus(_) => MsgCode::PortStatus
                // _ => MsgCode::Hello
            }
        }

        fn size_of(msg: &Message) -> usize {
            match *msg {
                Message::Hello => OfpHeader::size(),
                Message::FeaturesReq => OfpHeader::size(),
                Message::FlowMod(ref flow_mod) => OfpHeader::size() + FlowMod::size_of(flow_mod),
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
                Message::FeaturesReq => (),
                Message::FlowMod(flow_mod) => FlowMod::marshal(flow_mod, bytes),
                Message::PortStatus(sts) => PortStatus::marshal(sts, bytes),
                _ => ()
            }
        }

        pub fn marshal(xid: u32, msg: Message) -> Vec<u8> {
            let hdr = Self::header_of(xid, &msg);
            let mut bytes = vec![];
            OfpHeader::marshal(&mut bytes, hdr);
            Message::marshal_body(msg, &mut bytes);
            bytes
        }

        pub fn parse(header: &OfpHeader, buf: &[u8]) -> (u32, Message) {
            let typ = header.type_code();
            let msg = match typ {
                MsgCode::Hello => {
                    println!("Hello!");
                    Message::Hello
                }
                MsgCode::FeaturesResp => {
                    println!("FeaturesResp");
                    Message::FeaturesReply(SwitchFeatures::parse(buf))
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
            check_overlap: false
        }
    }
}
