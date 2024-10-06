use core::fmt;
use uefi::prelude::*;
use uefi::{Result};

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

pub const NET_ETHER_ADDR_LEN: usize = 6;
pub const NET_ETHER_HEAD_SIZE: usize = 14;

// Ethernet frame header definition.
#[repr(C, packed)]
#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub dst_mac: [u8; NET_ETHER_ADDR_LEN],
    pub src_mac: [u8; NET_ETHER_ADDR_LEN],
    pub ether_type: EtherProtoType,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(packet: &'a [u8]) -> Result<EthernetFrame<'a>> {
        if packet.len() < NET_ETHER_HEAD_SIZE {
            return Err(Status::INVALID_PARAMETER.into());
        }

        let dst_mac = packet[0..NET_ETHER_ADDR_LEN].try_into().unwrap();
        let src_mac = packet[NET_ETHER_ADDR_LEN..2 * NET_ETHER_ADDR_LEN].try_into().unwrap();
        let ether_type_raw = u16::from_be_bytes([packet[12], packet[13]]);
        let ether_type = EtherProtoType::from_u16(ether_type_raw);
        let payload = &packet[NET_ETHER_HEAD_SIZE..];

        Ok(EthernetFrame {
            dst_mac,
            src_mac,
            ether_type,
            payload,
        })
    }
}