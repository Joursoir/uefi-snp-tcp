#![no_std]
#![no_main]

use log::{error, warn, info};
use core::convert::TryInto;
use core::fmt;
use uefi::boot::{self, SearchType};
use uefi::prelude::*;
use uefi::proto::network::snp::{SimpleNetwork, NetworkMode, NetworkState};
use uefi::{Identify, Result};

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

#[entry]
fn efi_main() -> Status {
    uefi::helpers::init().unwrap(); // Initialize uefi::helpers

    start_net_interface().unwrap();

    Status::SUCCESS
}

fn start_net_interface() -> Result {
    info!("Looking for Simple Network device...");
    let snp_handle =
        *boot::locate_handle_buffer(SearchType::ByProtocol(&SimpleNetwork::GUID))?
        .first()
        .expect("Simple Network Protocol is missing");

    // When we exclusive opens SNP protocol, the UEFI will remove any drivers 
    // that opened SNP with BY_DRIVER by calling the driver's Stop() function. In UEFI
    // network stack, MNP driver will open SNP 'BY_DRIVER'. So the code below exclusive
    // opens SNP, MNP will uninstall itself and the whole UEFI network stack is
    // disconnected except SNP and UNDI.
    let snp = boot::open_protocol_exclusive::<SimpleNetwork>(
        snp_handle,
    )?;

    let network_mode: &NetworkMode = snp.mode();

    // When an EFI_SIMPLE_NETWORK_PROTOCOL driver initializes a
    // network interface, the network interface is left in the EfiSimpleNetworkStopped state.
    match network_mode.state {
        NetworkState::STOPPED => {
            info!("Network interface is currently stopped.");
        }
        NetworkState::STARTED => {
            warn!("Network interface is started but not yet initialized.");
            return Ok(())
        }
        NetworkState::INITIALIZED => {
            warn!("Network interface is fully initialized.");
            return Ok(())
        }
        _ => {
            error!("Invalid network state");
            return Err(Status::UNSUPPORTED.into());
        }
    }

    info!("Proceeding with network setup...");
    // Change the state of a network from “Stopped” to “Started”
    snp.start().unwrap();
    // Reset a network adapter and allocate the transmit and receive buffers
    snp.initialize(1024, 1024).unwrap();

    info!("Waiting for packets...");
    loop {
        let mut buffer = [0u8; 1024];
        let mut header_size = 0;

        let packet_size = match snp.receive(&mut buffer, Some(&mut header_size), None, None, None) {
            Ok(size) => size,
            Err(err) => {
                // Check if the error indicates that the network interface is not ready
                if err.status() != Status::NOT_READY {
                    error!("Error receiving packet: {:?}", err);
                }
                continue;
            }
        };

        let eth_frame = match EthernetFrame::parse(&buffer[..packet_size]) {
            Ok(frame) => frame,
            Err(err) => {
                error!("Error parsing Ethernet Frame: {:?}", err);
                continue;
            }
        };

        let ether_type = eth_frame.ether_type;

        info!("We got a packet from {} protocol.", ether_type);
        match ether_type {
            EtherProtoType::ARP => {
                ()
            },
            EtherProtoType::IPv4 | EtherProtoType::IPv6 | EtherProtoType::Unknown(_) => {
                warn!("Ignore the packet, not implemented");
                continue;
            }
        }

        let arp_packet = match ArpPacket::parse(&eth_frame.payload[..]) {
            Ok(packet) => packet,
            Err(err) => {
                error!("Error parsing Ethernet Frame: {:?}", err);
                continue;
            }
        };

        info!("Received packet: {:?}", &buffer[..packet_size]);
        info!("Header size: {}", header_size);

        /* TODO: parse ARP */
    }

    info!("Shutting down the network...");
    // Reset a network adapter, leaving it in a state that is safe for another driver to initialize
    snp.shutdown().unwrap();
    // Change the state of a network interface from “Started” to “Stopped”.
    snp.stop().unwrap();
    Ok(())
}
