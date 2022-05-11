use knx_ip_client::transport::udp::UdpTransport;
use log::info;
use snafu::Whatever;

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();
    let client = UdpTransport::connect("192.168.1.149:3671").await?;

    let value = client.read_group_address_value("5/1/0".try_into().unwrap()).await?;
    info!("Read value {:?}", value);

    Ok(())
}
