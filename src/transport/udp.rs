use crate::packets::tunneling::FeatureSet;
use std::time::Duration;
use tokio::time::timeout;
use std::sync::Arc;
use std::{net::SocketAddr, io::Cursor};

use log::{debug, warn, info};
use snafu::{Whatever, whatever};
use tokio::net::{UdpSocket, ToSocketAddrs};
use tokio::sync::{Mutex, mpsc};

use crate::packets::tunneling::KnxIpFeature;
use crate::packets::{core::{ConnectionstateResponse, ConnectionstateRequest, HPAI, ConnectionRequest, ConnectionResponse, DisconnectRequest, DisconnectResponse}, addresses::KnxAddress, emi::{LDataReqMessage, CEMI, CEMIMessageCode, LDataCon, LDataInd}, tunneling::{TunnelingRequest, TunnelingAck}, tpdu::TPDU, apdu::APDU};

pub type TransportResult<T> = Result<T, Whatever>;

enum TunnelingResponse {
    TunnelingRequest(TunnelingRequest),
    TunnelingAck(TunnelingAck),
    DisconnectResponse(DisconnectResponse),
}

struct UdpTransport {
    socket: Arc<UdpSocket>,
    communication_channel_id: u8,
    control_endpoint: HPAI,
    sequence_nr: Arc<Mutex<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<CEMI>>>,
}

impl UdpTransport {
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
        debug!("Sending connection request {:0x?}", req);
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
                            let resp = match UdpTransport::parse_response(data) {
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

    pub async fn get_connectionstate(&self) -> TransportResult<ConnectionstateResponse> {
        let req = ConnectionstateRequest::new(self.communication_channel_id, self.control_endpoint.clone());
        if let Err(e) = self.socket.send(&req.packet()).await {
            whatever!("Unable to send connection state request {:?}", e);
        };

        let mut resp = vec![0; 100];
        if let Err(e) = self.socket.recv(&mut resp).await {
            whatever!("Connectionstate not responded {:?}", e);
        }
        debug!("Connectiostate response {:0x?}", resp);
        let mut cursor = Cursor::new(resp.as_slice());
        ConnectionstateResponse::from_packet(&mut cursor)
    }

    pub async fn tunnel_req(&self, req: Vec<u8>) -> Result<(), Whatever> {
        let sequence_nr = self.get_next_sequence_nr().await;
        let tunneled_req = TunnelingRequest::new(self.communication_channel_id, sequence_nr, req);
        debug!("TunnelingRequest {:?}", tunneled_req);
        let req = tunneled_req.packet();
        debug!("Raw tunnel request: {:02x?}", req);
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }
        Ok(())
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
            },
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

pub struct UdpClient {
    transport: Arc<Mutex<UdpTransport>>,
}

impl UdpClient {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Whatever> {
        let transport = Arc::new(Mutex::new(UdpTransport::connect(addr).await?));

        Ok(Self {transport})
    }

    pub async fn read_group_address_value(&self, addr: KnxAddress) -> TransportResult<Vec<u8>> {
        let expected_addr = addr.to_u16();
        let apdu = APDU::group_value_read();
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let transport = self.transport.lock().await;
        transport.tunnel_req(req.packet()).await?;
        let mut rx = transport.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                    let data_con = LDataCon::from_cemi(cemi);
                    debug!("Parsed confirmation cEMI {:?}", data_con);
                }
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LDataInd as u8 => {
                    let data_ind = LDataInd::from_cemi(cemi)?;
                    debug!("Parsed indication cEMI {:?}", data_ind);
                    if data_ind.l_data.dest == expected_addr {
                        return Ok(data_ind.value);
                    }
                }
                Some(cemi) => whatever!("Unknown cEMI message code {:?}", cemi.msg_code),
                None => whatever!("No more data will be received from client"),
            }
        }
    }


    pub async fn flush(&self) -> Result<(), Whatever> {
        Ok(())
    }

    pub async fn write_group_address_value(&self, addr: KnxAddress, value: Vec<u8>) -> TransportResult<Vec<u8>> {
        let apdu = APDU::group_value_write(value);
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let transport = self.transport.lock().await;
        transport.tunnel_req(req.packet()).await?;
        let mut rx = transport.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                    let data_con = LDataCon::from_cemi(cemi);
                    debug!("Parsed confirmation cEMI {:?}", data_con);
                    continue;
                }
                Some(cemi) if cemi.msg_code == CEMIMessageCode::LDataInd as u8 => {
                    let data_ind = LDataInd::from_cemi(cemi)?;
                    debug!("Parsed indication cEMI {:?}", data_ind);
                    return Ok(data_ind.value);
                }
                Some(cemi) => whatever!("Unknown cEMI message code {:?}", cemi.msg_code),
                None => whatever!("No more data will be received from client"),
            }
        }
    }

    pub async fn disconnect(&self) -> Result<u8, Whatever> {
        self.transport.lock().await.disconnect().await
    }
}

#[cfg(test)]
mod tests {
    use log::info;

    use super::*;

    #[tokio::test]
    async fn test_connect() {
        env_logger::try_init();
        let mock_server = UdpSocket::bind("0.0.0.0:0").await.expect("Unable to bind to local UDP port");
        let addr = mock_server.local_addr().expect("Mock server should have a valid local address");
        tokio::spawn(async move {
            let mut connection_req = vec![0; 100];
            let (_, peer) = mock_server.recv_from(&mut connection_req).await.expect("Unable to receive connection request");
            info!("[Mock server] Received {:02x?}", connection_req);
            let mock_resp = vec![0x06, 0x10, 0x02, 0x06, 0x00, 0x14, 0x08, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            mock_server.send_to(&mock_resp, peer).await.expect("Unable to send mock connection response");
            info!("[Mock server] Sended mock response");
        });

        let client = UdpTransport::connect(addr).await.expect("Unable to connect with mock server");
        assert_eq!(client.get_communication_channel_id(), 8, "Communication channel id should be 8");
    }

    #[tokio::test]
    async fn test_get_connectionstate() {
        env_logger::try_init();
        let mock_server = UdpSocket::bind("0.0.0.0:0").await.expect("Unable to bind to local UDP port");
        let addr = mock_server.local_addr().expect("Mock server should have a valid local address");

        tokio::spawn(async move {
            let mut connection_req = vec![0; 100];
            let (_, peer) = mock_server.recv_from(&mut connection_req).await.expect("Unable to receive connection request");
            info!("[Mock server] Received {:02x?}", connection_req);
            let mock_resp = vec![0x06, 0x10, 0x02, 0x06, 0x00, 0x14, 0x08, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            mock_server.send_to(&mock_resp, peer).await.expect("Unable to send mock connection response");
            info!("[Mock server] Sended mock response");

            let mut connectionstate_req = vec![0; 100];
            let (_, peer) = mock_server.recv_from(&mut connectionstate_req).await.expect("Unable to receive connection state request");
            let mut cursor = Cursor::new(connectionstate_req.as_slice());
            let req = ConnectionstateRequest::from_packet(&mut cursor).expect("Invalid connectionstate request");
            info!("[Mock server] Received connection state request {:?}", req);
            let connectionstate_resp = ConnectionstateResponse { communication_channel_id: req.communication_channel_id, status: 0 };
            mock_server.send_to(&connectionstate_resp.packet(), peer).await.expect("Unable to respond to connection state request");
        });

        let client = UdpTransport::connect(addr).await.expect("Unable to connect with mock server");
        let state = client.get_connectionstate().await.expect("Should be able to request connectionstate");
        assert_eq!(state.communication_channel_id, client.get_communication_channel_id(), "Communication channel id should match client value");
        assert_eq!(state.status, 0, "Connection state should be ok");
    }
}
