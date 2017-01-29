use std::collections::HashMap;
use std::net::TcpStream;
use rust_ofp::ofp_controller::openflow0x01::OF0x01Controller;
use rust_ofp::openflow0x01::{Action, PacketIn, PacketOut, Pattern, PseudoPort, SwitchFeatures};
use rust_ofp::openflow0x01::message::{add_flow, parse_payload};

pub struct LearningSwitch {
    known_hosts: HashMap<[u8; 6], u16>,
}

impl LearningSwitch {
    fn learning_packet_in(&mut self, pkt: &PacketIn) {
        let pk = parse_payload(&pkt.input_payload);
        self.known_hosts.insert(pk.dl_src, pkt.port);
    }

    fn routing_packet_in(&mut self, sw: u64, pkt: PacketIn, stream: &mut TcpStream) {
        let pk = parse_payload(&pkt.input_payload);
        let pkt_dst = pk.dl_dst;
        let pkt_src = pk.dl_src;
        let out_port = self.known_hosts.get(&pkt_dst);
        match out_port {
            Some(p) => {
                let src_port = pkt.port;
                let mut src_dst_match = Pattern::match_all();
                src_dst_match.dl_dst = Some(pkt_dst);
                src_dst_match.dl_src = Some(pkt_src);
                let mut dst_src_match = Pattern::match_all();
                dst_src_match.dl_dst = Some(pkt_src);
                dst_src_match.dl_src = Some(pkt_dst);
                println!("Installing rule for host {:?} to {:?}.", pkt_src, pkt_dst);
                let actions = vec![Action::Output(PseudoPort::PhysicalPort(*p))];
                Self::send_flow_mod(sw, 0, add_flow(10, src_dst_match, actions), stream);
                println!("Installing rule for host {:?} to {:?}.", pkt_dst, pkt_src);
                let actions = vec![Action::Output(PseudoPort::PhysicalPort(src_port))];
                Self::send_flow_mod(sw, 0, add_flow(10, dst_src_match, actions), stream);
                let pkt_out = PacketOut {
                    output_payload: pkt.input_payload,
                    port_id: None,
                    apply_actions: vec![Action::Output(PseudoPort::PhysicalPort(*p))],
                };
                Self::send_packet_out(sw, 0, pkt_out, stream)
            }
            None => {
                println!("Known Hosts:\t{:?}", self.known_hosts);
                println!("Flooding to {:?}", pkt_dst);
                let pkt_out = PacketOut {
                    output_payload: pkt.input_payload,
                    port_id: None,
                    apply_actions: vec![Action::Output(PseudoPort::AllPorts)],
                };
                Self::send_packet_out(sw, 0, pkt_out, stream)
            }
        }
    }
}

impl OF0x01Controller for LearningSwitch {
    fn new() -> LearningSwitch {
        LearningSwitch { known_hosts: HashMap::new() }
    }

    fn switch_connected(&mut self, _: u64, _: SwitchFeatures, _: &mut TcpStream) {}

    fn switch_disconnected(&mut self, _: u64) {}

    fn packet_in(&mut self, sw: u64, _: u32, pkt: PacketIn, stream: &mut TcpStream) {
        println!("{:?}", pkt);
        self.learning_packet_in(&pkt);
        self.routing_packet_in(sw, pkt, stream);
    }
}
