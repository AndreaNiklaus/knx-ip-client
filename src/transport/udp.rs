use std::{net::SocketAddr, io::Cursor};

use log::debug;
use snafu::{Whatever, whatever};
use tokio::net::{UdpSocket, ToSocketAddrs};

use crate::packets::{core::{ConnectionstateResponse, ConnectionstateRequest, HPAI, ConnectionRequest, ConnectionResponse}, addresses::KnxAddress, emi::{LDataReqMessage, CEMI, CEMIMessageCode}, tunneling::TunnelingRequest};

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
        let req = LDataReqMessage::new(addr);
        println!("LDataReq {:?}", req);

        let tunneled_req = TunnelingRequest::new(self.communication_channel_id, 0, req.packet());
        println!("TunnelingRequest {:?}", tunneled_req);
        let req = tunneled_req.packet();
        println!("Read Group Value request: {:02x?}", req);
        self.socket.send(&req).await.expect("Unable to send request");

        let mut resp = vec![0; 100];
        match self.socket.recv(&mut resp).await {
            Ok(len) => len,
            Err(_) => {
                println!("Resend last packet");
                self.socket.send(&req).await.expect("Unable to resend request");
                match self.socket.recv(&mut resp).await {
                    Ok(len) => len,
                    Err(e) => {
                        eprintln!("{:?}", e);
                        0
                    }
                }
            }
        };
        println!("Read Group Value response: {:02x?}", resp);
        let mut resp = vec![0; 100];
        self.socket.recv(&mut resp).await.expect("Unable to get response");
        println!("Read Group Value response: {:02x?}", resp);
        let mut resp_cursor = Cursor::new(resp.as_slice());
        match TunnelingRequest::from_packet(&mut resp_cursor) {
            Ok(parsed_resp) => {
                println!("Read Group Value response: {:?}", parsed_resp);
                let mut cemi_cursor = Cursor::new(parsed_resp.get_cemi().as_slice());
                let parsed_cemi = CEMI::from_packet(&mut cemi_cursor);

                match parsed_cemi {
                    Ok(cemi) => {
                        println!("Read Group Value cEMI response {:?}", cemi);
                        if cemi.msg_code == CEMIMessageCode::LDataCon as u8 {
                            let data_con = LDataCon::from_cemi(cemi);
                            println!("Parsed cEMI {:?}", data_con);
                        }
                    },
                    Err(e) => eprintln!("Error parsing cEMI response {:?}", e),
                }
            },
            Err(e) => {
                eprintln!("Unable to parse read group response {:?}", e);
            }
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
