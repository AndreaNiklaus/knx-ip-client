use crate::packets::core::ConnectionRequest;
use crate::packets::core::ConnectionResponse;
use crate::packets::core::DisconnectRequest;
use crate::packets::core::DisconnectResponse;
use crate::packets::core::HPAI;
use crate::packets::emi::CEMIMessageCode;
use crate::packets::emi::LDataCon;
use crate::packets::emi::LDataInd;
use crate::packets::emi::CEMI;
use crate::packets::tunneling::FeatureResp;
use crate::packets::tunneling::FeatureSet;
use crate::packets::tunneling::KnxIpFeature;
use crate::packets::tunneling::TunnelingAck;
use crate::packets::tunneling::TunnelingRequest;
use log::debug;
use log::info;
use log::warn;
use snafu::whatever;
use snafu::Whatever;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::ToSocketAddrs;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

enum TunnelingResponse {
    TunnelingRequest(TunnelingRequest),
    TunnelingAck(TunnelingAck),
    FeatureResponse(FeatureResp),
    DisconnectResponse(DisconnectResponse),
}

struct UdpMonitorTransport {
    socket: Arc<UdpSocket>,
    communication_channel_id: u8,
    control_endpoint: HPAI,
    sequence_nr: Arc<Mutex<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<CEMI>>>,
}

impl UdpMonitorTransport {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Whatever> {
        let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let socket = match UdpSocket::bind(local_addr).await {
            Ok(socket) => socket,
            Err(e) => whatever!("Unable to get a local address {:?}", e),
        };
        debug!("Connecting with address target KnxIp");
        if let Err(e) = socket.connect(addr).await {
            whatever!("Unable to connect with target {:?}", e);
        }

        let req = ConnectionRequest::tunnel().packet();
        debug!("Sending tunnel connection request {:0x?}", req);
        socket.send(&req).await.expect("Unable to send request");

        let mut resp = vec![0; 100];
        if let Err(e) = socket.recv(&mut resp).await {
            whatever!("Target device does not respond {:?}", e);
        }
        debug!("Connection response {:0x?}", resp);

        let mut resp_cursor = Cursor::new(resp.as_slice());
        let connection = ConnectionResponse::from_packet(&mut resp_cursor)?;
        debug!("Parsed Connection response {:?}", connection);

        let (from_knx_tx, rx) = mpsc::channel(100);
        let socket = Arc::new(socket);
        let s = socket.clone();
        tokio::spawn(async move {
            loop {
                let mut data = vec![0; 100];
                tokio::select! {
                    count = s.recv(&mut data) => {
                        if count.is_ok() && count.unwrap() > 0 {
                            let resp = match UdpMonitorTransport::parse_response(data) {
                                Ok(resp) => resp,
                                Err(e) => {
                                    warn!("Unable to parse tunneling response. {:?}", e);
                                    continue;
                                }
                            };
                            match resp {
                                TunnelingResponse::TunnelingRequest(req) => {
                                    let ack = TunnelingAck::new(req.communication_channel_id, req.sequence_nr, 0);
                                    if let Err(e) = s.send(&ack.packet()).await {
                                        warn!("Unable to send tunneling ack to knxip target {:?}", e);
                                    }

                                    let mut cemi = Cursor::new(req.get_cemi().as_slice());

                                    let cemi = match CEMI::from_packet(&mut cemi) {
                                        Ok(cemi) => cemi,
                                        Err(e) => {
                                            warn!("Error parsing cEMI response {:?}", e);
                                            continue;
                                        }
                                    };
                                    match from_knx_tx.send(cemi).await {
                                            Ok(_) => (),
                                            Err(e) => warn!("Unable to pass received request from knx device, {:?}", e),
                                    };
                                },
                                TunnelingResponse::TunnelingAck(_) => {

                                },
                                TunnelingResponse::FeatureResponse(resp) => {
                                    let ack = TunnelingAck::new(resp.communication_channel_id, resp.sequence_nr, 0);

                                    if let Err(e) = s.send(&ack.packet()).await {
                                        warn!("Unable to send tunneling ack to knxip target {:?}", e);
                                    }
                                },
                                TunnelingResponse::DisconnectResponse(resp) => {
                                    if resp.status == 0 {
                                        info!("Successfully disconnected");
                                        break;
                                    } else {
                                        warn!("Unable to disconnect, status code {:?}", resp);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            socket,
            communication_channel_id: connection.get_communication_channel_id(),
            control_endpoint: connection.get_data_endpoint(),
            sequence_nr: Arc::new(Mutex::new(0)),
            rx: Arc::new(Mutex::new(rx)),
        })
    }

    async fn get_next_sequence_nr(&self) -> u8 {
        let mut sequence_nr = self.sequence_nr.lock().await;
        let num = *sequence_nr;
        *sequence_nr = sequence_nr.wrapping_add(1);
        num
    }

    pub fn get_communication_channel_id(&self) -> u8 {
        self.communication_channel_id
    }

    pub async fn set_feature(&self, feature: KnxIpFeature, value: u8) -> Result<(), Whatever> {
        let sequence_nr = self.get_next_sequence_nr().await;
        let req = FeatureSet::new(self.communication_channel_id, sequence_nr, feature, value);
        debug!("FeatureSet request {:?}", req);
        let req = req.packet();
        debug!("Raw tunnel request: {:02x?}", req);
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<u8, Whatever> {
        let req = DisconnectRequest::new(self.communication_channel_id, self.control_endpoint.clone()).packet();
        debug!("Request disconnect for connection {}", self.communication_channel_id);
        self.socket.send(&req).await.expect("Unable to send request");

        let mut resp = vec![0; 100];
        self.socket.recv(&mut resp).await.expect("Unable to get response");
        let mut resp_cursor = Cursor::new(resp.as_slice());

        match DisconnectResponse::from_packet(&mut resp_cursor) {
            Ok(resp) => {
                debug!("Disconnect response status {}", resp.status);
                Ok(resp.status)
            }
            Err(e) => whatever!("Unable to request disconnection for id {}, {:?}", self.communication_channel_id, e),
        }
    }

    pub fn parse_response(resp: Vec<u8>) -> Result<TunnelingResponse, Whatever> {
        debug!("TunnelingResponse: {:02x?}", resp);
        let response_code = resp.get(2..4);
        if response_code.is_some() {
            if response_code == Some(&vec![0x04, 0x20]) {
                debug!("Received tunneling request");
                let mut resp_cursor = Cursor::new(resp.as_slice());
                let resp = TunnelingRequest::from_packet(&mut resp_cursor)?;
                debug!("Parsed tunneling request {:?}", resp);
                Ok(TunnelingResponse::TunnelingRequest(resp))
            } else if response_code == Some(&vec![0x04, 0x21]) {
                debug!("Received tunneling ack");
                let mut resp_cursor = Cursor::new(resp.as_slice());
                let resp = TunnelingAck::from_packet(&mut resp_cursor)?;
                debug!("Parsed tunneling ack {:?}", resp);
                Ok(TunnelingResponse::TunnelingAck(resp))
            } else if response_code == Some(&vec![0x04, 0x23]) {
                debug!("Received feature response");
                let mut resp_cursor = Cursor::new(resp.as_slice());
                let resp = FeatureResp::from_packet(&mut resp_cursor)?;
                debug!("Parsed feature response {:?}", resp);
                Ok(TunnelingResponse::FeatureResponse(resp))
            } else if response_code == Some(&vec![0x02, 0x0a]) {
                debug!("Received disconnection response");
                let mut resp_cursor = Cursor::new(resp.as_slice());
                let resp = DisconnectResponse::from_packet(&mut resp_cursor)?;
                debug!("Parsed disconnect response {:?}", resp);
                Ok(TunnelingResponse::DisconnectResponse(resp))
            } else {
                whatever!("Unknown response code {:?}", response_code);
            }
        } else {
            whatever!("Tunneling response without a valid code {:?}", response_code)
        }
    }
}

pub struct UdpMonitor {
    transport: Arc<Mutex<UdpMonitorTransport>>,
}

impl UdpMonitor {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Whatever> {
        let transport = Arc::new(Mutex::new(UdpMonitorTransport::connect(addr).await?));

        transport.lock().await.set_feature(KnxIpFeature::InfoServiceEnable, 1).await?;

        Ok(Self { transport })
    }

    pub async fn disconnect(&self) -> Result<u8, Whatever> {
        self.transport.lock().await.disconnect().await
    }

    pub async fn next_msg(&self) -> Result<LDataInd, Whatever> {
        loop {
            match self.transport.lock().await.rx.lock().await.recv().await {
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
                None => whatever!("Closed connection"),
            }
        }
    }
}
