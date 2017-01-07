use std::net::{TcpListener, TcpStream};

extern crate rust_ofp;
use rust_ofp::ofp_controller::OfpController;
use rust_ofp::ofp_controller::openflow0x01::OF0x01Controller;
use rust_ofp::openflow0x01::{SwitchFeatures, PacketIn, Pattern};
use rust_ofp::openflow0x01::message::{add_flow, Message};

fn main() {
    struct OF0x01;
    impl OF0x01Controller for OF0x01 {
        fn switch_connected(_: u64, _: SwitchFeatures, stream: &mut TcpStream) {
            let prio = 0;
            let pat = Pattern::match_all();
            let message = Message::FlowMod(add_flow(prio, pat, vec![]));
            Self::send_message(1000, message, stream)
        }

        fn switch_disconnected(_: u64) {
        }

        fn packet_in(_: u64, _: u32, _: PacketIn, _: &mut TcpStream) {
        }
    }

    let listener = TcpListener::bind(("127.0.0.1", 6633)).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                std::thread::spawn(move || LearningSwitch::handle_client_connected(&mut stream));
            }
            Err(_) => {
                // connection failed
                panic!("Connection failed")
            }
        }
    }
}
