#![crate_name = "rust_of"]
#![crate_type = "lib"]

extern crate byteorder;
extern crate rustc_serialize;

pub mod ofp_header;
pub mod openflow0x01;

mod rust_of {
    pub use super::*;
}
