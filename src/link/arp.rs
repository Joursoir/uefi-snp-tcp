use uefi::prelude::*;
use uefi::{Result};

// The Address Resolution Protocol (ARP) does not have a fixed header size.
// The size of an ARP message depends on the address sizes of both the link layer
// and the network layer. However, since we are specifically working with an Ethernet stack,
// we are not supporting other hardware types.
//
// As far as we are focused on Ethernet, we can assume a fixed ARP header size,
// since we know the hardware and protocol types. RFC 826 says:
//
// In theory, the length fields (ar$hln and ar$pln) are redundant,
// since the length of a protocol address should be determined by
// the hardware type (found in ar$hrd) and the protocol type (found
// in ar$pro). It is included for optional consistency checking,
// and for network monitoring and debugging (see below).
//
// In our case:
// Hardware (Ethernet) address length is 6 bytes.
// Protocol (IPv4) address length is 4 bytes.

pub const NET_ARP_HEAD_SIZE: usize = 2 + 2 + 2 + 2 + (NET_ARP_ETH_HLEN * 2) + (NET_ARP_IPV4_PLEN * 2); // 28
pub const NET_ARP_ETH_HLEN: usize = 6;
pub const NET_ARP_IPV4_PLEN: usize = 4;

pub struct ArpPacket<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < NET_ARP_HEAD_SIZE {
            return Err(Status::INVALID_PARAMETER.into());
        }

        Ok(Self { buffer })
    }

    pub fn set_htype(&mut self, hardware_type: u16) {
        self.buffer[0] = (hardware_type >> 8) as u8;
        self.buffer[1] = hardware_type as u8;
    }

    pub fn htype(&self) -> u16 {
        ((self.buffer[0] as u16) << 8) | (self.buffer[1] as u16)
    }

    pub fn set_ptype(&mut self, protocol_type: u16) {
        self.buffer[2] = (protocol_type >> 8) as u8;
        self.buffer[3] = protocol_type as u8;
    }

    pub fn ptype(&self) -> u16 {
        ((self.buffer[2] as u16) << 8) | (self.buffer[3] as u16)
    }

    pub fn set_hlen(&mut self, hardware_address_length: u8) {
        self.buffer[4] = hardware_address_length;
    }

    pub fn hlen(&self) -> u8 {
        self.buffer[4]
    }

    pub fn set_plen(&mut self, protocol_address_length: u8) {
        self.buffer[5] = protocol_address_length;
    }

    pub fn plen(&self) -> u8 {
        self.buffer[5]
    }

    pub fn set_oper(&mut self, operation: u16) {
        self.buffer[6] = (operation >> 8) as u8;
        self.buffer[7] = operation as u8;
    }

    pub fn oper(&self) -> u16 {
        ((self.buffer[6] as u16) << 8) | (self.buffer[7] as u16)
    }

    pub fn set_sha(&mut self, sender_hardware_address: &[u8; NET_ARP_ETH_HLEN]) {
        self.buffer[8] = sender_hardware_address[0];
        self.buffer[9] = sender_hardware_address[1];
        self.buffer[10] = sender_hardware_address[2];
        self.buffer[11] = sender_hardware_address[3];
        self.buffer[12] = sender_hardware_address[4];
        self.buffer[13] = sender_hardware_address[5];
    }

    pub fn sha(&self) -> &[u8] {
        &self.buffer[8..14]
    }

    pub fn set_spa(&mut self, sender_protocol_address: &[u8; NET_ARP_IPV4_PLEN]) {
        self.buffer[14] = sender_protocol_address[0];
        self.buffer[15] = sender_protocol_address[1];
        self.buffer[16] = sender_protocol_address[2];
        self.buffer[17] = sender_protocol_address[3];
    }

    pub fn spa(&self) -> &[u8] {
        &self.buffer[14..18]
    }

    pub fn set_tha(&mut self, target_hardware_address: &[u8; NET_ARP_ETH_HLEN]) {
        self.buffer[18] = target_hardware_address[0];
        self.buffer[19] = target_hardware_address[1];
        self.buffer[20] = target_hardware_address[2];
        self.buffer[21] = target_hardware_address[3];
        self.buffer[22] = target_hardware_address[4];
        self.buffer[23] = target_hardware_address[5];
    }

    pub fn tha(&self) -> &[u8] {
        &self.buffer[18..24]
    }

    pub fn set_tpa(&mut self, target_protocol_address: &[u8; NET_ARP_IPV4_PLEN]) {
        self.buffer[24] = target_protocol_address[0];
        self.buffer[25] = target_protocol_address[1];
        self.buffer[26] = target_protocol_address[2];
        self.buffer[27] = target_protocol_address[3];
    }

    pub fn tpa(&self) -> &[u8] {
        &self.buffer[24..28]
    }
}