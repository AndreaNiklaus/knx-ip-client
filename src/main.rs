use std::sync::Arc;
use knx_ip_client::{transport::udp::UdpClient, dp_types::{PdtKnxFloat, PdtKnxScaledValue, PdtKnxBit}};
use log::{info, debug, warn};
use snafu::Whatever;

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();
    let client = Arc::new(UdpMonitor::connect("192.168.1.149:3671").await?);

    let off = PdtKnxBit::switch(false);
    let resp = client.write_group_address_value("1/0/0".try_into().unwrap(), off.get_bytes()).await?;
    // let percent = PdtKnxScaledValue::scaling(50.0);
    // let resp = client.write_group_address_value("1/4/3".try_into().unwrap(), percent.get_bytes()).await?;
    info!("Write group address response {:?}", resp);

    // let reason = read(client.clone()).await;
    // warn!("Unable to read from knx {:?}", reason);

    client.disconnect().await?;

    Ok(())
}

// async fn read(client: Arc<UdpClient>) -> Result<(), Whatever> {
//     loop {
//         let value = client.read_group_address_value("2/0/0".try_into().unwrap()).await?;
//         debug!("Read value {:?}", value);
//         let pdt = PdtKnxFloat::temp_from_bytes(value)?;
//         info!("Read value {:?}", pdt.get_value());
//         tokio::time::sleep(std::time::Duration::from_millis(500)).await;
//     }
// }
