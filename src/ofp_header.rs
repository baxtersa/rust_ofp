use std::io::Cursor;
use std::mem::{size_of, transmute};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

use rust_ofp::openflow0x01::MsgCode;

#[derive(RustcEncodable, RustcDecodable)]
pub struct OfpHeader {
    version: u8,
    typ: u8,
    length: u16,
    xid: u32,
}

impl OfpHeader {
    pub fn new(version: u8, typ: u8, length: u16, xid: u32) -> OfpHeader {
        OfpHeader {
            version: version,
            typ: typ,
            length: length,
            xid: xid,
        }
    }

    pub fn size() -> usize {
        size_of::<OfpHeader>()
    }

    pub fn marshal(bytes: &mut Vec<u8>, header: OfpHeader) {
        bytes.write_u8(header.version()).unwrap();
        bytes.write_u8(header.type_code() as u8).unwrap();
        bytes.write_u16::<BigEndian>(header.length() as u16).unwrap();
        bytes.write_u32::<BigEndian>(header.xid()).unwrap();
    }

    pub fn parse(buf: [u8; 8]) -> Self {
        let mut bytes = Cursor::new(buf.to_vec());
        OfpHeader {
            version: bytes.read_u8().unwrap(),
            typ: bytes.read_u8().unwrap(),
            length: bytes.read_u16::<BigEndian>().unwrap(),
            xid: bytes.read_u32::<BigEndian>().unwrap(),
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn type_code(&self) -> MsgCode {
        unsafe { transmute(self.typ) }
    }
    pub fn length(&self) -> usize {
        self.length as usize
    }
    pub fn xid(&self) -> u32 {
        self.xid
    }
}
