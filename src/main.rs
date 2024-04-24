use knx_ip_client::{
    dp_types::{PdtKnxB1U3, PdtKnxBit, PdtKnxFloat, PdtKnxScaledValue}, packets::addresses::KnxAddress, transport::udp::UdpClient
};
use log::{info, warn};
use snafu::{ResultExt, Whatever};
use std::{sync::Arc, thread::sleep, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::init();
    let client = Arc::new(UdpClient::connect("192.168.10.19:3671").await?);

    sleep(Duration::from_secs(2));

/*
    let resp = client.read_group_address_value(KnxAddress::try_from("1/2/1").unwrap()).await;
    info!("Read 1: {:?}", resp);

    if let Ok(resp) = resp {
        match PdtKnxBit::from_bytes(resp) {
            Ok(data) => info!("Read lamp status {:?}", data.get_value()),
            Err(e) => warn!("Unable to read lamp status {:?}", e),
        }
    }
*/

    let switch_on = PdtKnxBit::switch(false);
    let resp = client.write_group_address_value(KnxAddress::try_from("1/0/1").unwrap(), switch_on.get_bytes()).await;
    info!("Write 1: {:?}", resp);

    sleep(Duration::from_secs(2));

    let switch_on = PdtKnxBit::switch(true);
    let resp = client.write_group_address_value(KnxAddress::try_from("1/0/1").unwrap(), switch_on.get_bytes()).await;
    info!("Write 1: {:?}", resp);

    let resp = client.read_group_address_value(KnxAddress::try_from("1/3/1").unwrap()).await;
    info!("Read 2: {:?}", resp);

    if let Ok(resp) = resp {
        match PdtKnxScaledValue::from_bytes(&resp) {
            Ok(data) => info!("Read lamp dimming {:?}%", data.get_value()),
            Err(e) => warn!("Unable to read lamp dimming {:?}", e),
        }
    }

    sleep(Duration::from_secs(2));
    let dim_down_10 = PdtKnxB1U3::dimming(false, 3);
    let resp = client.write_group_address_value(KnxAddress::try_from("1/1/1").unwrap(), dim_down_10.get_bytes()).await;
    info!("Write 2: {:?}", resp);

    // let resp = client.read_group_address_value(KnxAddress::try_from("2/1/4").unwrap()).await;
    // info!("Read 1: {:?}", resp);

    // if let Ok(resp) = resp {
    //     let data = PdtKnxFloat::temp_from_bytes(resp);
    //     info!("Read temp {:?}", data.map(|pdt| pdt.get_value()));
    // }

    // let resp = client.read_group_address_value(KnxAddress::try_from("2/1/4").unwrap()).await;
    // info!("Read 2: {:?}", resp);

    // if let Ok(resp) = resp {
    //     let data = PdtKnxFloat::temp_from_bytes(resp);
    //     info!("Read temp {:?}", data.map(|pdt| pdt.get_value()));
    // }


    // let off = PdtKnxBit::switch(false);
    // let resp = client
    //     .write_group_address_value("1/0/0".try_into().unwrap(), off.get_bytes())
    //     .await
    //     .map_err(|_| "Unable to write group address");
    // let percent = PdtKnxScaledValue::scaling(50.0);
    // let resp = client.write_group_address_value("1/4/3".try_into().unwrap(), percent.get_bytes()).await?;
    // info!("Write group address response {:?}", resp);

    // let reason = read(client.clone()).await;
    // warn!("Unable to read from knx {:?}", reason);

    info!("Request disconnection");
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
