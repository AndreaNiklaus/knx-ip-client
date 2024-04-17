use crate::packets::addresses::KnxAddress;
use crate::packets::apdu::APDU;
use crate::packets::core::ConnectionRequest;
use crate::packets::core::ConnectionResponse;
use crate::packets::core::ConnectionstateRequest;
use crate::packets::core::ConnectionstateResponse;
use crate::packets::core::DisconnectRequest;
use crate::packets::core::DisconnectResponse;
use crate::packets::core::HPAI;
use crate::packets::emi::CEMIMessageCode;
use crate::packets::emi::LDataCon;
use crate::packets::emi::LDataInd;
use crate::packets::emi::LDataReqMessage;
use crate::packets::emi::CEMI;
use crate::packets::tpdu::TPDU;
use crate::packets::tunneling::FeatureResp;
use crate::packets::tunneling::FeatureSet;
use crate::packets::tunneling::KnxIpFeature;
use crate::packets::tunneling::TunnelingAck;
use crate::packets::tunneling::TunnelingRequest;
use crate::transport::udp::connect;
use crate::transport::udp::handle_recv_from_knx_device;
use log::debug;
use log::info;
use log::warn;
use snafu::ensure_whatever;
use snafu::whatever;
use snafu::ResultExt;
use snafu::Whatever;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio::time::timeout;
use std::fmt::Debug;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::ToSocketAddrs;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::interval;

struct ConnectionData {
    communication_channel_id: u8,
    control_endpoint: HPAI,
    sequence_nr: u8,
}

impl ConnectionData {
    pub fn from_connection_response(connection: ConnectionResponse) -> Self {
        Self {
            sequence_nr: 1,
            communication_channel_id: connection.get_communication_channel_id(),
            control_endpoint: connection.get_data_endpoint(),
        }
    }
}

struct UdpMonitorTransport {
    socket: Arc<UdpSocket>,
    connection_data: Arc<Mutex<Option<ConnectionData>>>,
    rx: Arc<Mutex<mpsc::Receiver<CEMI>>>,
}

impl UdpMonitorTransport {
    pub async fn connect<A: ToSocketAddrs + Debug + Clone>(addr: A) -> Result<Self, Whatever> {
        let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let socket = UdpSocket::bind(local_addr).await
            .with_whatever_context(|e| format!("Unable to get local address {:?}", e))?;
        let socket = Arc::new(socket);

        let debug_addr = format!("{:?}", addr);
        debug!("Connecting with KnxIp {}", debug_addr);
        if let Err(e) = socket.connect(addr).await {
            whatever!("Unable to connect with target {:?}", e);
        }
        debug!("Connected with KnxIp {}", debug_addr);

        let connection_data: Arc<Mutex<Option<ConnectionData>>> = Arc::new(Mutex::new(None));

        let (from_knx_tx, rx) = mpsc::channel(100);

        tokio::spawn({
            let socket = socket.clone();
            let connection_data = connection_data.clone();

            async move {
                // Interval should be 60 seconds as stated in
                // 03_08_02 Core section 5.4
                //
                let mut heart_beat = interval(Duration::from_secs(60));
                // prevents many heart beats when connection disconnect and restores
                //
                heart_beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                loop {

                    // If connection data is none we don't have a valid connection
                    // with KNXIP device
                    //
                    if connection_data.lock().await.is_none() {
                        info!("No valid connection with KNXIP device, create it");
                        let connection = connect(socket.clone()).await;
                        let communication_channel_id = connection.get_communication_channel_id();

                        if enable_busmonitor(&socket, communication_channel_id).await.is_err() {
                            continue;
                        }

                        info!("Created communication channel ID {:?}", communication_channel_id);
                        let mut connection_data = connection_data.lock().await;
                        *connection_data = Some(ConnectionData::from_connection_response(connection));
                    }

                    loop {
                        tokio::select! {
                            resp = handle_recv_from_knx_device(socket.clone(), from_knx_tx.clone()) => {
                                info!("Recieve messages from knx device task exited with result {:?}", resp);
                            }
                            _ = heart_beat.tick() => {
                                info!("Send connection heart beat");
                                let req = {
                                    let guard = connection_data.lock().await;
                                    match guard.as_ref() {
                                        Some(data) => {
                                            ConnectionstateRequest::new(
                                                data.communication_channel_id,
                                                data.control_endpoint.clone(),
                                            )
                                        },
                                        None => break,
                                    }
                                };
                                if let Err(e) = socket.send(&req.packet()).await {
                                    warn!("Unable to send connection state request {:?}", e);
                                    break;
                                };
                            }
                        }
                    }

                    let mut data = connection_data.lock().await;
                    *data = None;
                }
            }
        });

        Ok(Self {
            socket,
            connection_data,
            rx: Arc::new(Mutex::new(rx)),
        })
    }

    async fn communication_channel_id(&self) -> Result<u8, Whatever> {
        match self.connection_data.lock().await.as_ref() {
            Some(data) => Ok(data.communication_channel_id),
            None => whatever!("Disconnected from knx device, ID"),
        }
    }

    async fn control_endpoint(&self) -> Result<HPAI, Whatever> {
        match self.connection_data.lock().await.as_ref() {
            Some(data) => Ok(data.control_endpoint.clone()),
            None => whatever!("Disconnected from knx device, HPAI"),
        }
    }

    async fn get_next_sequence_nr(&self) -> Result<u8, Whatever> {
        match self.connection_data.lock().await.as_mut() {
            Some(data) => {
                let num = data.sequence_nr;
                data.sequence_nr = data.sequence_nr.wrapping_add(1);
                Ok(num)
            },
            None => whatever!("Disconnected from knx device, NR"),
        }
    }

    pub async fn set_feature(&self, feature: KnxIpFeature, value: u8) -> Result<(), Whatever> {
        let sequence_nr = self.get_next_sequence_nr().await?;
        let req = FeatureSet::new(self.communication_channel_id().await?, sequence_nr, feature, value);
        debug!("FeatureSet request {:?}", req);
        let req = req.packet();
        debug!("Raw tunnel request: {:02x?}", req);
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<u8, Whatever> {
        let communication_channel_id = self.communication_channel_id().await?;
        let req =
            DisconnectRequest::new(communication_channel_id, self.control_endpoint().await?)
                .packet();
        debug!(
            "Request disconnect for connection {}",
            communication_channel_id
        );
        self.socket
            .send(&req)
            .await
            .expect("Unable to send request");

        let mut resp = vec![0; 100];
        self.socket
            .recv(&mut resp)
            .await
            .expect("Unable to get response");
        let mut resp_cursor = Cursor::new(resp.as_slice());

        match DisconnectResponse::from_packet(&mut resp_cursor) {
            Ok(resp) => {
                debug!("Disconnect response status {}", resp.status);
                Ok(resp.status)
            }
            Err(e) => whatever!(
                "Unable to request disconnection for id {}, {:?}",
                communication_channel_id,
                e
            ),
        }
    }

}

async fn enable_busmonitor(socket: &Arc<UdpSocket>, communication_channel_id: u8) -> Result<usize, Whatever> {
    let sequence_nr = 0;
    let req = FeatureSet::new(communication_channel_id, sequence_nr, KnxIpFeature::InfoServiceEnable, 1);
    debug!("FeatureSet request {:?}", req);
    let req = req.packet();
    debug!("Raw tunnel request: {:02x?}", req);
    socket
        .send(&req)
        .await
        .with_whatever_context(|e| format!("Unable to send request {:?}", e))
}

pub struct UdpMonitor {
    transport: Arc<Mutex<UdpMonitorTransport>>,
}

impl UdpMonitor {
    pub async fn connect(addr: &str) -> Result<Self, Whatever> {
        let transport = Self::create_transport(addr.into()).await?;

        Ok(Self { transport: Arc::new(Mutex::new(transport)) })
    }

    pub async fn disconnect(&self) -> Result<u8, Whatever> {
        self.transport.lock().await.disconnect().await
    }

    async fn create_transport(addr: String) -> Result<UdpMonitorTransport, Whatever> {
        let transport = UdpMonitorTransport::connect(addr).await?;

        Ok(transport)
    }

    pub async fn next_msg(&self) -> Result<LDataInd, Whatever> {
        let rx = { self.transport.lock().await.rx.clone() };
        loop {
            match rx.lock().await.recv().await {
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                    let data_con = LDataCon::from_cemi(cemi);
                    debug!("Parsed confirmation cEMI {:?}", data_con);
                    continue;
                }
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LDataInd as u8 => {
                    let data_ind = LDataInd::from_cemi(cemi)?;
                    debug!("Parsed indication cEMI {:?}", data_ind);
                    return Ok(data_ind);
                }
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LBusmonInd as u8 => {
                    debug!("To parse busmod {:0x?}", cemi.service_info);
                    let data_ind = LDataInd::from_cemi(cemi)?;
                    debug!("Parsed indication cEMI {:?}", data_ind);
                    return Ok(data_ind);
                }
                Some(cemi) => {
                    debug!("Unknown CEMI message code {:?}", cemi);
                    continue;
                }
                None => {
                    whatever!("Transport is closed");
                },
            }
        }
    }

    pub async fn solecitate_group_read(&self, addr: KnxAddress) -> Result<(), Whatever> {
        info!("Read {:?}", addr);
        let apdu = APDU::group_value_read();
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let transport = self.transport.lock().await;
        if let Err(e) = transport.socket.send(&req.packet()).await {
            whatever!("Unable to send connection state request {:?}", e);
        };
        Ok(())
    }

}
