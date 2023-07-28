//! This example shows how to discover KNX devices on the network.
//!
//! `cargo run --example discovery`
//!
//! Output:
//!
//! ```text
//! ⊙ 192.168.0.203:3671
//! ⏵ Name: MDT KNX TP IP
//! ⏵ Medium: TP1
//! ⏵ Individual Addr: 15.15.0
//! ⏵ Programming Mode: no
//! ⏵ Project Installation ID: 0
//! ⏵ Serial: [0, 1, 2, 3, 4, 5]
//! ⏵ Multicast Addr: 224.0.23.12
//! ⏵ MAC Addr: [0, 1, 2, 3, 4, 5]
//! ⏵⏵ Service Family: 2 Version: 2
//! ⏵⏵ Service Family: 3 Version: 2
//! ⏵⏵ Service Family: 4 Version: 2
//! ⏵⏵ Service Family: 5 Version: 2
//! ⏵⏵ Service Family: 7 Version: 2
//! ```

use knx_ip_client::packets::core::{DeviceStatus, SearchResponse};
use knx_ip_client::transport::udp::UdpClient;
use log::info;
use snafu::Whatever;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();

    let devices = UdpClient::search(Duration::from_millis(100)).await?;
    info!("Received {} responses", devices.len());

    for response in devices {
        let SearchResponse {
            control_endpoint,
            device_hardware,
            supported_service_families,
        } = response;

        let programming_status = if device_hardware.knx_device_status == DeviceStatus::PROGRAMMING_MODE {
            "yes"
        } else {
            "no"
        };

        println!("⊙ {}", control_endpoint.address);
        println!("⏵ Name: {}", &device_hardware.friendly_name()?);
        println!("⏵ Medium: {:?}", device_hardware.knx_medium);
        println!("⏵ Individual Addr: {:?}", device_hardware.knx_individual_address);
        println!("⏵ Programming Mode: {}", programming_status);
        println!("⏵ Project Installation ID: {}", device_hardware.project_installation_identifier);
        println!("⏵ Serial: {:?}", device_hardware.serial_number);
        println!("⏵ Multicast Addr: {}", device_hardware.routing_multicast_address);
        println!("⏵ MAC Addr: {:?}", device_hardware.mac_address);

        for family in supported_service_families.service_families {
            println!("⏵⏵ Service Family: {:?} Version: {:?}", family.service_family, family.version);
        }

        println!();
    }

    Ok(())
}
