use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};

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

pub enum Action {
    Output(PseudoPort),
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
    pub out_port: Option<PseudoPort>
}

pub mod message {
    use super::*;
    use ofp_header::OfpHeader;

    pub enum Message {
        Hello,
        FeaturesReq,
        FeaturesReply(SwitchFeatures),
        FlowMod(FlowMod)
    }

    impl Message {
        fn msg_code_of_message(msg: &Message) -> MsgCode {
            match *msg {
                Message::Hello => MsgCode::Hello,
                Message::FeaturesReq => MsgCode::FeaturesReq,
                Message::FeaturesReply(_) => MsgCode::FeaturesResp,
                Message::FlowMod(_) => MsgCode::FlowMod
                // _ => MsgCode::Hello
            }
        }

        fn size_of(msg: &Message) -> usize {
            match *msg {
                Message::Hello => OfpHeader::size(),
                Message::FeaturesReq => OfpHeader::size(),
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

        pub fn marshal(xid: u32, msg: Message) -> Vec<u8> {
            let hdr = Self::header_of(xid, &msg);
            let mut bytes = vec![];
            OfpHeader::marshal(&mut bytes, hdr);
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
            out_port: None
        }
    }
}
