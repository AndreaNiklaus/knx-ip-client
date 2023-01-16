use std::sync::Arc;
use knx_ip_client::{transport::udp_monitor::UdpMonitor, dp_types::{PdtKnxFloat, PdtKnxScaledValue}};
use knx_ip_client::packets::addresses::IndividualAddress;
use knx_ip_client::packets::addresses::Group3LevelAddress;
use log::{info, debug, warn};
use snafu::Whatever;

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();
    let client = Arc::new(UdpMonitor::connect("192.168.1.149:3671").await?);

    // let percent = PdtKnxScaledValue::scaling(50.0);
    // let resp = client.write_group_address_value("1/4/3".try_into().unwrap(), percent.get_bytes()).await?;
    // info!("Write group address response {:?}", resp);

    // let reason = read(client.clone()).await;
    // warn!("Unable to read from knx {:?}", reason);

    for i in 0..10 {
        let msg = client.next_msg().await.unwrap();
        let percent = PdtKnxScaledValue::from_bytes(&msg.value).get_value();
        info!("Msg {:?}: {:?}->{:?} value = {}%", i, IndividualAddress::from_u16(msg.l_data.src), Group3LevelAddress::from_u16(msg.l_data.dest), percent);
    }

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
