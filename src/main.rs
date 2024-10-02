#![no_std]
#![no_main]

use log::{error, warn, info};
use uefi::boot::{self, SearchType};
use uefi::prelude::*;
use uefi::proto::network::snp::{SimpleNetwork, NetworkMode, NetworkState};
use uefi::{Identify, Result};

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

    /* TODO: handle packets */

    info!("Shutting down the network...");
    // Reset a network adapter, leaving it in a state that is safe for another driver to initialize
    snp.shutdown().unwrap();
    // Change the state of a network interface from “Started” to “Stopped”.
    snp.stop().unwrap();
    Ok(())
}
