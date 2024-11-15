use core::fmt;
use uefi::prelude::*;
use uefi::{Result};

use super::checksum::internet_checksum;

const NET_IPV4_MIN_HEADER_LENGTH: usize = 20;

pub struct Ipv4Writer<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> Ipv4Writer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < NET_IPV4_MIN_HEADER_LENGTH {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn header_len(&self) -> usize {
        (self.buffer[0] & 0x0f) as usize * 4
    }

    pub fn set_version(&mut self, version: u8) {
        self.buffer[0] = (self.buffer[0] & 0x0F) | (version << 4);
    }

    pub fn set_ihl(&mut self, ihl: u8) {
        self.buffer[0] = (self.buffer[0] & 0xF0) | (ihl & 0x0F);
    }

    pub fn set_total_length(&mut self, total_length: u16) {
        self.buffer[2] = (total_length >> 8) as u8;
        self.buffer[3] = (total_length & 0xFF) as u8;
    }

    pub fn set_id(&mut self, identification: u16) {
        self.buffer[4] = (identification >> 8) as u8;
        self.buffer[5] = (identification & 0xFF) as u8;
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.buffer[6] = (self.buffer[6] & 0x1F) | ((flags << 5) & 0xE0);
    }

    pub fn set_fragment_offset(&mut self, fragment_offset: u16) {
        self.buffer[6] = (self.buffer[6] & 0xE0) | ((fragment_offset >> 8) & 0x1F) as u8;
        self.buffer[7] = (fragment_offset & 0xFF) as u8;
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.buffer[8] = ttl;
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.buffer[9] = protocol;
    }

    pub fn set_src_ip(&mut self, src_ip: &[u8; 4]) {
        self.buffer[12] = src_ip[0];
        self.buffer[13] = src_ip[1];
        self.buffer[14] = src_ip[2];
        self.buffer[15] = src_ip[3];
    }

    pub fn set_dest_ip(&mut self, dest_ip: &[u8; 4]) {
        self.buffer[16] = dest_ip[0];
        self.buffer[17] = dest_ip[1];
        self.buffer[18] = dest_ip[2];
        self.buffer[19] = dest_ip[3];
    }

    pub fn calc_checksum(&mut self) {
        self.buffer[10] = 0;
        self.buffer[11] = 0;
        let checksum = internet_checksum(&self.buffer[..self.header_len()]);
        self.buffer[10] = (checksum >> 8) as u8;
        self.buffer[11] = (checksum & 0xff) as u8;
    }

    pub fn payload(&mut self) -> &mut [u8] {
        let start = self.header_len();

        &mut self.buffer[start..]
    }
}

pub struct Ipv4Reader<'a> {
    pub buffer: &'a [u8],
}

impl<'a> Ipv4Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < NET_IPV4_MIN_HEADER_LENGTH {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn version(&self) -> u8 {
        self.buffer[0] >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.buffer[0] & 0x0f
    }

    pub fn tos(&self) -> u8 {
        self.buffer[1]
    }

    pub fn total_length(&self) -> u16 {
        ((self.buffer[2] as u16) << 8) | (self.buffer[3] as u16)
    }

    pub fn id(&self) -> u16 {
        ((self.buffer[4] as u16) << 8) | (self.buffer[5] as u16)
    }

    pub fn flags(&self) -> u8 {
        self.buffer[6] >> 5
    }

    pub fn fragment_offset(&self) -> u16 {
        ((self.buffer[6] as u16 & 0x1F) << 8) | (self.buffer[7] as u16)
    }

    pub fn ttl(&self) -> u8 {
        self.buffer[8]
    }

    pub fn protocol(&self) -> u8 {
        self.buffer[9]
    }

    pub fn checksum(&self) -> u16 {
        ((self.buffer[10] as u16) << 8) | (self.buffer[11] as u16)
    }

    pub fn src_ip(&self) -> &[u8] {
        &self.buffer[12..16]
    }

    pub fn dest_ip(&self) -> &[u8] {
        &self.buffer[16..20]
    }

    pub fn header_len(&self) -> usize {
        self.ihl() as usize * 4
    }

    pub fn payload(&self) -> &[u8] {
        let start = self.header_len();

        &self.buffer[start..]
    }
}

impl fmt::Debug for Ipv4Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4Reader")
            .field("version", &self.version())
            .field("ihl (header length)", &format_args!("0x{:02x} ({:} bytes)",
                &self.ihl(), &self.header_len()))
            .field("tos", &format_args!("0x{:02x}", &self.tos()))
            .field("total_length", &self.total_length())
            .field("id", &format_args!("0x{:02x}", &self.id()))
            .field("flags", &format_args!("0x{:02x}", &self.flags()))
            .field("fragment_offset", &format_args!("0x{:02x}", &self.fragment_offset()))
            .field("ttl", &self.ttl())
            .field("protocol", &self.protocol())
            .field("checksum", &format_args!("0x{:02x}", &self.checksum()))
            .field("src_ip", &format_args!("{:?}", &self.src_ip()))
            .field("dest_ip", &format_args!("{:?}", &self.dest_ip()))
            .field("total length", &self.buffer.len())
            .finish_non_exhaustive()
    }
}
