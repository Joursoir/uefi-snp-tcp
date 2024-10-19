use core::fmt;
use uefi::prelude::*;
use uefi::{Result};

pub const NET_ETHER_ADDR_LEN: usize = 6;
pub const NET_ETHER_HEAD_SIZE: usize = 14;

pub struct EthernetWriter<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> EthernetWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < NET_ETHER_HEAD_SIZE {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn set_dest_mac(&mut self, dest: &[u8; NET_ETHER_ADDR_LEN]) {
        self.buffer[0] = dest[0];
        self.buffer[1] = dest[1];
        self.buffer[2] = dest[2];
        self.buffer[3] = dest[3];
        self.buffer[4] = dest[4];
        self.buffer[5] = dest[5];
    }

    pub fn set_src_mac(&mut self, src: &[u8; NET_ETHER_ADDR_LEN]) {
        self.buffer[6] = src[0];
        self.buffer[7] = src[1];
        self.buffer[8] = src[2];
        self.buffer[9] = src[3];
        self.buffer[10] = src[4];
        self.buffer[11] = src[5];
    }

    pub fn set_ethertype(&mut self, ethertype: u16) {
        self.buffer[12] = (ethertype >> 8) as u8;
        self.buffer[13] = (ethertype & 0xFF) as u8;
    }

    // FIXME: buffer can be big enough, so we have to come up with solution
    // that will determinate effective size of payload
    pub fn payload(&mut self) -> &mut [u8] {
        let len_no_fcs = self.buffer.len() - 4;
        &mut self.buffer[NET_ETHER_HEAD_SIZE..len_no_fcs]
    }

    // TODO: calculate FCS
}

pub struct EthernetReader<'a> {
    pub buffer: &'a [u8],
}

impl<'a> EthernetReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < NET_ETHER_HEAD_SIZE {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn dest_mac(&self) -> &[u8] {
        &self.buffer[0..6]
    }

    pub fn src_mac(&self) -> &[u8] {
        &self.buffer[6..12]
    }

    pub fn ethertype(&self) -> (u16, EtherProtoType) {
        let proto_type: u16 = ((self.buffer[12] as u16) << 8) | (self.buffer[13] as u16);
        (proto_type, EtherProtoType::from_u16(proto_type))
    }

    pub fn payload(&self) -> &[u8] {
        let len_no_fcs = self.buffer.len() - 4;
        &self.buffer[NET_ETHER_HEAD_SIZE..len_no_fcs]
    }
}

// Ethernet protocol type definitions.
#[derive(Debug, Clone, Copy)]
pub enum EtherProtoType {
    ARP,
    IPv4,
    IPv6,
    Unknown(u16),
}

impl EtherProtoType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0806 => EtherProtoType::ARP,
            0x0800 => EtherProtoType::IPv4,
            0x86DD => EtherProtoType::IPv6,
            other => EtherProtoType::Unknown(other),
        }
    }
}

impl fmt::Display for EtherProtoType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol_str = match self {
            EtherProtoType::ARP => "ARP",
            EtherProtoType::IPv4 => "IPv4",
            EtherProtoType::IPv6 => "IPv6",
            EtherProtoType::Unknown(value) => return write!(f, "Unknown(0x{:04X})", value),
        };
        write!(f, "{}", protocol_str)
    }
}
