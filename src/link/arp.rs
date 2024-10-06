use uefi::prelude::*;
use uefi::{Result};

pub const NET_ARP_HEAD_SIZE: usize = 8;

// ARP packet definition based on RFC 826
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket<'a> {
    pub hw_type: u16,             // Hardware type
    pub proto_type: u16,          // Protocol type
    pub hw_addr_len: u8,          // Hardware address length
    pub proto_addr_len: u8,       // Protocol address length
    pub op_code: u16,             // Operation code
    pub sender_hw_addr: &'a [u8], // Hardware address of sender (length: hw_addr_len)
    pub sender_proto_addr: &'a [u8], // Protocol address of sender (length: proto_addr_len)
    pub target_hw_addr: &'a [u8], // Hardware address of target (length: hw_addr_len)
    pub target_proto_addr: &'a [u8], // Protocol address of target (length: proto_addr_len)
    pub payload: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<ArpPacket<'a>> {
        if buffer.len() < NET_ARP_HEAD_SIZE {
            return Err(Status::INVALID_PARAMETER.into());
        }

        let hw_type = u16::from_be_bytes([buffer[0], buffer[1]]);
        let proto_type = u16::from_be_bytes([buffer[2], buffer[3]]);
        let hw_addr_len = buffer[4];
        let proto_addr_len = buffer[5];
        let op_code = u16::from_be_bytes([buffer[6], buffer[7]]);

        let ha_len = hw_addr_len as usize;
        let pa_len = proto_addr_len as usize;
        let header_length = NET_ARP_HEAD_SIZE + (ha_len*2) + (pa_len*2);
        if buffer.len() < header_length {
            return Err(Status::INVALID_PARAMETER.into());
        }

        let sender_hw_addr = &buffer[8..(8 + ha_len)];
        let sender_proto_addr = &buffer[(8 + ha_len)..(8 + ha_len + pa_len)];
        let target_hw_addr = &buffer[(8 + ha_len + pa_len)..(8 + ha_len + pa_len + ha_len)];
        let target_proto_addr = &buffer[(8 + ha_len + pa_len + ha_len)..header_length];
        let payload = &buffer[header_length..];

        Ok(ArpPacket {
            hw_type,
            proto_type,
            hw_addr_len,
            proto_addr_len,
            op_code,
            sender_hw_addr,
            sender_proto_addr,
            target_hw_addr,
            target_proto_addr,
            payload,
        })
    }
}