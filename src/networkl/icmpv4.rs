use uefi::prelude::*;
use uefi::{Result};

use super::checksum::internet_checksum;

pub const NET_ICMPV4_HEADER_LENGTH: usize = 8;
pub const NET_ICMPV4_TYPE_ECHO_REQ: u8 = 8;
pub const NET_ICMPV4_TYPE_ECHO_REP: u8 = 0;

pub struct Icmpv4Writer<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> Icmpv4Writer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < NET_ICMPV4_HEADER_LENGTH {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn set_type(&mut self, icmp_type: u8) {
        self.buffer[0] = icmp_type;
    }

    pub fn set_code(&mut self, code: u8) {
        self.buffer[1] = code;
    }

    pub fn calc_checksum(&mut self) {
        self.buffer[2] = 0;
        self.buffer[3] = 0;
        let checksum = internet_checksum(self.buffer);
        self.buffer[2] = (checksum >> 8) as u8;
        self.buffer[3] = (checksum & 0xff) as u8;
    }
}

pub struct Icmpv4Reader<'a> {
    pub buffer: &'a [u8],
}

impl<'a> Icmpv4Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < NET_ICMPV4_HEADER_LENGTH {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn r#type(&self) -> u8 {
        self.buffer[0]
    }

    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    pub fn checksum(&self) -> u16 {
        ((self.buffer[2] as u16) << 8) | (self.buffer[3] as u16)
    }

    pub fn is_echo_request(&self) -> bool {
        self.r#type() == NET_ICMPV4_TYPE_ECHO_REQ
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer[NET_ICMPV4_HEADER_LENGTH..]
    }
}
