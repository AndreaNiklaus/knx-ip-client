use knx_ip_client::{transport::udp::UdpTransport, dp_types::{PdtKnxFloat, PdtKnxScaledValue}};
use log::{info, debug};
use snafu::Whatever;

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();
    let client = UdpTransport::connect("192.168.1.149:3671").await?;

    let value = client.read_group_address_value("2/0/0".try_into().unwrap()).await?;
    info!("Read value {:?}", value);

    let pdt = PdtKnxFloat::temp_from_bytes(value)?;
    info!("Read value {:?}", pdt.get_value());

    client.flush().await;

    let percent = PdtKnxScaledValue::scaling(50.0);
    let resp = client.write_group_address_value("1/4/3".try_into().unwrap(), percent.get_bytes()).await?;

    client.disconnect().await?;

    Ok(())
}
