use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

extern crate rust_ofp;
use rust_ofp::ofp_header::*;
use rust_ofp::openflow0x01::Pattern;
use rust_ofp::openflow0x01::message::{add_flow, Message};

fn send_message(xid: u32, message: Message, writer: &mut TcpStream) {
    let raw_msg = Message::marshal(xid, message);
    writer.write_all(&raw_msg).unwrap()
}

fn implement_flow(_: u64, writer: &mut TcpStream) {
    // Drop all packets at each switch on arrival.
    let prio = 0;
    let pat = Pattern::match_all();
    let message = Message::FlowMod(add_flow(prio, pat, vec![]));
    send_message(1000, message, writer)
}

fn process_message(xid: u32, message: Message, writer: &mut TcpStream) {
    match message {
        Message::EchoRequest(bytes) => send_message(xid, Message::EchoReply(bytes), writer),
        Message::Hello => send_message(10, Message::FeaturesReq, writer),
        Message::FeaturesReply(fts) => implement_flow(fts.datapath_id, writer),
        _ => println!("Unsupported message type"),
    }
}

fn handle_client(stream: &mut TcpStream) {
    send_message(0, Message::Hello, stream);

    let mut buf = [0u8; 8];

    loop {
        let res = stream.read(&mut buf);
        match res {
            Ok(num_bytes) if num_bytes > 0 => {
                let header = OfpHeader::parse(buf);
                let message_len = header.length() - OfpHeader::size();
                let mut message_buf = vec![0; message_len];
                let _ = stream.read(&mut message_buf);
                let (xid, body) = Message::parse(&header, &message_buf);
                process_message(xid, body, stream)
            }
            Ok(_) => {
                println!("Connection closed reading header.");
                break;
            }
            Err(e) => println!("{}", e),
        }
    }
}

fn main() {
    let listener = TcpListener::bind(("127.0.0.1", 6633)).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => handle_client(&mut stream),
            Err(_) => {
                // connection failed
                panic!("Connection failed")
            }
        }
    }
}
