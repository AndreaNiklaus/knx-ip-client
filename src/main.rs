use knx_ip_client::{transport::udp::UdpTransport, packets::addresses::KnxAddress};
use log::info;
use snafu::Whatever;

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();
    let client = UdpTransport::connect("192.168.1.149:3671").await?;

    let value = client.read_group_address_value(KnxAddress::group_3_level(5, 0, 1)).await?;
    info!("Read value {:?}", value);

    Ok(())
}
