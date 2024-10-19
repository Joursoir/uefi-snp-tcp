#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use log::{error, warn, info};
use uefi::boot::{self, ScopedProtocol, SearchType};
use uefi::prelude::*;
use uefi::proto::network::snp::{SimpleNetwork, NetworkMode, NetworkState};
use uefi::{Identify, Result};
use crate::{
    link::{
        arp::{ArpWriter, ArpReader, NET_ARP_OPER_REQUEST, NET_ARP_OPER_REPLY},
        ethernet::{EthernetFrame, EtherProtoType, NET_ETHER_ADDR_LEN},
    },
};

mod link;

#[entry]
fn efi_main() -> Status {
    uefi::helpers::init().unwrap(); // Initialize uefi::helpers

    let snp = start_net_interface().unwrap();
    let retval = packet_processing_loop(&snp);
    stop_net_interface(snp).unwrap();

    retval.status()
}

fn handle_arp(
    snp: &ScopedProtocol<SimpleNetwork>,
    payload: &mut [u8],
    packet_size: usize
) -> Result {
    let network_mode: &NetworkMode = snp.mode();
    let arp_packet = match ArpReader::new(payload) {
        Ok(packet) => packet,
        Err(err) => {
            error!("Error parsing Ethernet Frame: {:?}", err);
            return Err(Status::BAD_BUFFER_SIZE.into());
        }
    };

    if arp_packet.oper() == NET_ARP_OPER_REQUEST {
        let mut response_packet: Vec<u8> = vec![0u8; packet_size];
        // response_packet.copy_from_slice(&buffer[..packet_size]);

        let mut eth_response = EthernetFrame::new(&mut response_packet[..]).unwrap();
        let my_mac: &[u8; NET_ETHER_ADDR_LEN] = &network_mode.current_address.0[..NET_ETHER_ADDR_LEN].try_into().unwrap(); 
        // eth_response.set_dest_mac(eth_frame.src_mac().try_into().unwrap()); // blames on borrowing
        eth_response.set_dest_mac(arp_packet.sha().try_into().unwrap()); // fixme: dirty hack
        eth_response.set_src_mac(my_mac);
        eth_response.set_ethertype(0x0806); // ether_type_val

        let mut eth_payload = eth_response.payload();
        eth_payload.copy_from_slice(arp_packet.buffer);
        let mut arp_response = ArpWriter::new(&mut eth_payload).unwrap();
        arp_response.set_oper(NET_ARP_OPER_REPLY);
        arp_response.set_sha(my_mac);
        arp_response.set_spa(arp_packet.tpa().try_into().unwrap());
        arp_response.set_tha(arp_packet.sha().try_into().unwrap());
        arp_response.set_tpa(arp_packet.spa().try_into().unwrap());

        info!("{:?}", arp_response);
        snp.transmit(0, &response_packet, None, None, None)?;
    }

    Ok(())
}

fn packet_processing_loop(snp: &ScopedProtocol<SimpleNetwork>) -> Result {
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

        let mut eth_frame = match EthernetFrame::new(&mut buffer[..packet_size]) {
            Ok(frame) => frame,
            Err(err) => {
                error!("Error parsing Ethernet Frame: {:?}", err);
                continue;
            }
        };

        let (_, ether_type) = eth_frame.ethertype();
        let mut eth_payload = eth_frame.payload();

        info!("We got a packet from {} protocol.", ether_type);
        match ether_type {
            EtherProtoType::ARP => {
                handle_arp(snp, &mut eth_payload, packet_size)?;
            },
            EtherProtoType::IPv4 | EtherProtoType::IPv6 | EtherProtoType::Unknown(_) => {
                warn!("Ignore the packet, not implemented");
                continue;
            }
        }    
    }
}

fn start_net_interface() -> Result<ScopedProtocol<SimpleNetwork>> {
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
            return Err(Status::UNSUPPORTED.into());
        }
        NetworkState::INITIALIZED => {
            warn!("Network interface is fully initialized.");
            return Err(Status::UNSUPPORTED.into());
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
    Ok(snp)
}

fn stop_net_interface(snp: ScopedProtocol<SimpleNetwork>) -> Result {
    info!("Shutting down the network...");
    // Reset a network adapter, leaving it in a state that is safe for another driver to initialize
    snp.shutdown().unwrap();
    // Change the state of a network interface from “Started” to “Stopped”.
    snp.stop().unwrap();

    Ok(())
}
