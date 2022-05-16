use std::{net::SocketAddr, io::Cursor};

use log::{debug, warn};
use snafu::{Whatever, whatever};
use tokio::net::{UdpSocket, ToSocketAddrs};

use crate::packets::{core::{ConnectionstateResponse, ConnectionstateRequest, HPAI, ConnectionRequest, ConnectionResponse, DisconnectRequest, DisconnectResponse}, addresses::KnxAddress, emi::{LDataReqMessage, CEMI, CEMIMessageCode, LDataCon, LDataInd}, tunneling::{TunnelingRequest, TunnelingAck}, tpdu::TPDU, apdu::APDU};

pub type TransportResult<T> = Result<T, Whatever>;

pub struct UdpTransport {
    socket: UdpSocket,
    communication_channel_id: u8,
    control_endpoint: HPAI,
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


        Ok(Self {
            socket,
            communication_channel_id: connection.get_communication_channel_id(),
            control_endpoint: connection.get_data_endpoint(),
        })
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

    pub async fn read_group_address_value(&self, addr: KnxAddress) -> TransportResult<Vec<u8>> {
        let apdu = APDU::group_value_read();
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let tunneled_req = TunnelingRequest::new(self.communication_channel_id, 0, req.packet());
        debug!("TunnelingRequest {:?}", tunneled_req);
        let req = tunneled_req.packet();
        debug!("Read Group Value request: {:02x?}", req);
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }

        let mut resp = vec![0; 100];
        if let Err(e) = self.socket.recv(&mut resp).await {
            warn!("Unable to receive request {:?}, resend request packet", e);
            if let Err(e) = self.socket.send(&req).await {
                whatever!("Unable to resend read request {:?}", e);
            }
            if let Err(e) = self.socket.recv(&mut resp).await {
                whatever!("Unable to receive read response {:?}", e);
            }
        };
        let mut packet_cursor = Cursor::new(resp.as_slice());
        let tunnel_ack = TunnelingAck::from_packet(&mut packet_cursor)?;
        debug!("Tunneling Ack received {:?}", tunnel_ack);
        loop {
            let mut resp = vec![0; 100];
            if let Err(e) = self.socket.recv(&mut resp).await {
                whatever!("Unable to get response {:?}", e);
            }
            debug!("Read Group Value response: {:02x?}", resp);
            let mut resp_cursor = Cursor::new(resp.as_slice());
            match TunnelingRequest::from_packet(&mut resp_cursor) {
                Ok(parsed_resp) => {
                    debug!("Read Group Value response: {:?}", parsed_resp);
                    let mut cemi_cursor = Cursor::new(parsed_resp.get_cemi().as_slice());
                    let parsed_cemi = CEMI::from_packet(&mut cemi_cursor);

                    match parsed_cemi {
                        Ok(cemi) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                            let data_con = LDataCon::from_cemi(cemi);
                            debug!("Parsed cEMI {:?}", data_con);
                            let ack = TunnelingAck::new(parsed_resp.communication_channel_id, parsed_resp.sequence_nr, 0);
                            self.socket.send(&ack.packet()).await;
                        }
                        Ok(cemi) if cemi.msg_code == CEMIMessageCode::LDataInd as u8 => {
                            let data_ind = LDataInd::from_cemi(cemi)?;
                            debug!("Parsed cEMI {:?}", data_ind);
                            let ack = TunnelingAck::new(parsed_resp.communication_channel_id, parsed_resp.sequence_nr, 0);
                            self.socket.send(&ack.packet()).await;
                            return Ok(data_ind.value);
                        }
                        Ok(_) => break,
                        Err(e) => whatever!("Error parsing cEMI response {:?}", e),
                    }
                },
                Err(e) => {
                    whatever!("Unable to parse read group response {:?}", e);
                }
            }
        }

        whatever!("Unable to get read group response")
    }

    pub async fn flush(&self) {
        let mut buf = vec![0; 100];
        while self.socket.try_recv(&mut buf).is_ok() {};
    }

    pub async fn write_group_address_value(&self, addr: KnxAddress, value: Vec<u8>) -> TransportResult<Vec<u8>> {
        let apdu = APDU::group_value_write(value);
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let tunneled_req = TunnelingRequest::new(self.communication_channel_id, 0, req.packet());
        debug!("TunnelingRequest {:?}", tunneled_req);
        let req = tunneled_req.packet();
        debug!("Read Group Value request: {:02x?}", req);
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }

        let mut resp = vec![0; 100];
        if let Err(e) = self.socket.recv(&mut resp).await {
            warn!("Unable to receive request {:?}, resend request packet", e);
            if let Err(e) = self.socket.send(&req).await {
                whatever!("Unable to resend read request {:?}", e);
            }
            if let Err(e) = self.socket.recv(&mut resp).await {
                whatever!("Unable to receive read response {:?}", e);
            }
        };
        let mut packet_cursor = Cursor::new(resp.as_slice());
        let tunnel_ack = TunnelingAck::from_packet(&mut packet_cursor)?;
        debug!("Tunneling Ack received {:?}", tunnel_ack);
        loop {
            let mut resp = vec![0; 100];
            if let Err(e) = self.socket.recv(&mut resp).await {
                whatever!("Unable to get response {:?}", e);
            }
            debug!("Read Group Value response: {:02x?}", resp);
            let mut resp_cursor = Cursor::new(resp.as_slice());
            match TunnelingRequest::from_packet(&mut resp_cursor) {
                Ok(parsed_resp) => {
                    debug!("Read Group Value response: {:?}", parsed_resp);
                    let mut cemi_cursor = Cursor::new(parsed_resp.get_cemi().as_slice());
                    let parsed_cemi = CEMI::from_packet(&mut cemi_cursor);

                    match parsed_cemi {
                        Ok(cemi) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                            let data_con = LDataCon::from_cemi(cemi);
                            debug!("Parsed cEMI {:?}", data_con);
                            let ack = TunnelingAck::new(parsed_resp.communication_channel_id, parsed_resp.sequence_nr, 0);
                            self.socket.send(&ack.packet()).await;
                        }
                        Ok(cemi) if cemi.msg_code == CEMIMessageCode::LDataInd as u8 => {
                            let data_ind = LDataInd::from_cemi(cemi)?;
                            debug!("Parsed cEMI {:?}", data_ind);
                            let ack = TunnelingAck::new(parsed_resp.communication_channel_id, parsed_resp.sequence_nr, 0);
                            self.socket.send(&ack.packet()).await;
                            return Ok(data_ind.value);
                        }
                        Ok(_) => break,
                        Err(e) => whatever!("Error parsing cEMI response {:?}", e),
                    }
                },
                Err(e) => {
                    whatever!("Unable to parse read group response {:?}", e);
                }
            }
        }

        whatever!("Unable to get read group response")
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
