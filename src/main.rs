use std::net::TcpListener;

extern crate rust_ofp;
use rust_ofp::learning_switch::LearningSwitch;
use rust_ofp::ofp_controller::OfpController;

fn main() {
    let listener = TcpListener::bind(("127.0.0.1", 6633)).unwrap();
    for stream in listener.incoming() {
        println!("{:?}", stream);
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
