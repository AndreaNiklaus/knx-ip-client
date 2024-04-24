use crate::packets::core::{SearchRequest, SearchResponse, DISCOVERY_ENDPOINT_PORT, SYSTEM_MULTICAST_ADDRESS};
use crate::packets::tunneling::{FeatureResp, FeatureSet};
use crate::transport;
use std::sync::Arc;
use std::time::Duration;
use std::{io::Cursor, net::SocketAddr};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, sleep, timeout};
use tokio::{io, select};

use log::{debug, info, trace, warn};
use snafu::{ensure_whatever, whatever, ResultExt, Snafu, Whatever};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::{mpsc, Mutex};

use crate::packets::tunneling::KnxIpFeature;
use crate::packets::{
    addresses::KnxAddress,
    apdu::APDU,
    core::{ConnectionRequest, ConnectionResponse, ConnectionstateRequest, ConnectionstateResponse, DisconnectRequest, DisconnectResponse, HPAI},
    emi::{CEMIMessageCode, LDataCon, LDataInd, LDataReqMessage, CEMI},
    tpdu::TPDU,
    tunneling::{TunnelingAck, TunnelingRequest},
};

struct ConnectionData {
    communication_channel_id: u8,
    control_endpoint: HPAI,
    sequence_nr: u8,
}

impl ConnectionData {
    pub fn from_connection_response(connection: ConnectionResponse) -> Self {
        Self {
            sequence_nr: 0,
            communication_channel_id: connection.get_communication_channel_id(),
            control_endpoint: connection.get_data_endpoint(),
        }
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(whatever, display("{message}"))]
    GenericError {
        message: String,

        // Having a `source` is optional, but if it is present, it must
        // have this specific attribute and type:
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl From<Whatever> for Error {
    fn from(value: Whatever) -> Self {
        Self::GenericError {
            message: value.to_string(),
            source: None,
        }
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::GenericError { message: value, source: None }
    }
}

pub struct MyUdpSocket {
    pub inner: UdpSocket,
}

impl MyUdpSocket {
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        trace!("[OUT] {:02x?}", buf);
        self.inner.send(buf).await
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let resp = self.inner.recv(buf).await;
        if let Ok(count) = resp {
            trace!("[IN] {:02x?}", &buf[0..count]);
        }
        resp
    }
}

pub type TransportResult<T> = Result<T, Error>;

enum TunnelingResponse {
    TunnelingRequest(TunnelingRequest),
    TunnelingAck(TunnelingAck),
    FeatureResponse(FeatureResp),
    ConnectionstateResponse(ConnectionstateResponse),
    DisconnectResponse(DisconnectResponse),
    DisconnectRequest(DisconnectRequest),
}

struct UdpTransport {
    socket: Arc<MyUdpSocket>,
    connection_data: Arc<Mutex<Option<ConnectionData>>>,
    rx: Arc<Mutex<mpsc::Receiver<CEMI>>>,
}

impl UdpTransport {
    pub async fn connect<A: ToSocketAddrs + std::fmt::Debug>(addr: A) -> Result<Self, Whatever> {
        let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let socket = UdpSocket::bind(local_addr)
            .await
            .with_whatever_context(|e| format!("Unable to get local address {:?}", e))?;

        let debug_addr = format!("{:?}", addr);
        debug!("Connecting with KnxIp {}", debug_addr);
        if let Err(e) = socket.connect(addr).await {
            whatever!("Unable to connect with target {:?}", e);
        }
        debug!("Connected with KnxIp {}", debug_addr);
        let socket = Arc::new(MyUdpSocket { inner: socket });

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

                'main: loop {
                    // If connection data is none we don't have a valid connection
                    // with KNXIP device
                    //
                    if connection_data.lock().await.is_none() {
                        info!("No valid connection with KNXIP device, create it");
                        let connection = connect(socket.clone()).await;
                        let communication_channel_id = connection.get_communication_channel_id();

                        info!("Created communication channel ID {:?}", communication_channel_id);
                        let mut connection_data = connection_data.lock().await;
                        *connection_data = Some(ConnectionData::from_connection_response(connection));
                    }

                    'recv: loop {
                        tokio::select! {
                            resp = handle_recv_from_knx_device(socket.clone(), from_knx_tx.clone()) => {
                                info!("Recieve messages from knx device task exited with result {:?}", resp);
                                if resp.is_ok() {
                                    debug!("Exit from reconnection loop");
                                    break 'main;
                                } else {
                                    break 'recv;
                                }
                            },
                            _ = heart_beat.tick() => {
                                info!("Send connection heart beat");
                                match connection_data.lock().await.as_ref() {
                                    Some(&ref data) => {
                                        let req = ConnectionstateRequest::new(
                                            data.communication_channel_id,
                                            data.control_endpoint.clone(),
                                        );
                                        if let Err(e) = socket.send(&req.packet()).await {
                                            warn!("Unable to send connection state request {:?}", e);
                                            break;
                                        };
                                    },
                                    None => break,
                                };
                            }
                        }
                    }

                    let mut data = connection_data.lock().await;
                    *data = None;
                }
                debug!("UpdTransport receive task exited");
            }
        });

        Ok(Self {
            socket,
            connection_data,
            rx: Arc::new(Mutex::new(rx)),
        })
    }

    async fn get_next_sequence_nr(&self) -> Result<u8, Whatever> {
        match self.connection_data.lock().await.as_mut() {
            Some(data) => {
                let num = data.sequence_nr;
                data.sequence_nr = data.sequence_nr.wrapping_add(1);
                Ok(num)
            }
            None => whatever!("Disconnected from knx device, NR"),
        }
    }

    async fn get_communication_channel_id(&self) -> Result<u8, Whatever> {
        match self.connection_data.lock().await.as_ref() {
            Some(data) => Ok(data.communication_channel_id),
            None => whatever!("Disconnected from knx device, ID"),
        }
    }

    async fn get_control_endpoint(&self) -> Result<HPAI, Whatever> {
        match self.connection_data.lock().await.as_ref() {
            Some(data) => Ok(data.control_endpoint.clone()),
            None => whatever!("Disconnected from knx device, HPAI"),
        }
    }

    pub async fn get_connectionstate(&self) -> TransportResult<ConnectionstateResponse> {
        let req = ConnectionstateRequest::new(self.get_communication_channel_id().await?, self.get_control_endpoint().await?);
        if let Err(e) = self.socket.send(&req.packet()).await {
            whatever!("Unable to send connection state request {:?}", e);
        };

        let mut resp = vec![0; 100];
        if let Err(e) = self.socket.recv(&mut resp).await {
            whatever!("Connectionstate not responded {:?}", e);
        }
        debug!("Connectiostate response {:0x?}", resp);
        let mut cursor = Cursor::new(resp.as_slice());
        Ok(ConnectionstateResponse::from_packet(&mut cursor)?)
    }

    pub async fn tunnel_req(&self, req: Vec<u8>) -> Result<(), Whatever> {
        let sequence_nr = self.get_next_sequence_nr().await?;
        let tunneled_req = TunnelingRequest::new(self.get_communication_channel_id().await?, sequence_nr, req);
        debug!("TunnelingRequest {:?}", tunneled_req);
        let req = tunneled_req.packet();
        debug!("======================");
        debug!("[OUT] Raw tunnel request: {:02x?}", req);
        debug!("======================");
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }
        Ok(())
    }

    pub async fn set_feature(&self, feature: KnxIpFeature, value: u8) -> Result<(), Whatever> {
        let sequence_nr = self.get_next_sequence_nr().await?;
        let req = FeatureSet::new(self.get_communication_channel_id().await?, sequence_nr, feature, value);
        debug!("FeatureSet request {:?}", req);
        let req = req.packet();
        debug!("Raw tunnel request: {:02x?}", req);
        if let Err(e) = self.socket.send(&req).await {
            whatever!("Unable to send request {:?}", e);
        }
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<(), Whatever> {
        let req = DisconnectRequest::new(self.get_communication_channel_id().await?, self.get_control_endpoint().await?).packet();
        debug!("Request disconnect for connection {}", self.get_communication_channel_id().await?);
        self.socket.send(&req).await.expect("Unable to send request");

        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(_resp) => Ok(()),
            None => whatever!("Transport closed before disconnection response"),
        }
    }

    pub async fn search(timeout: Duration) -> Result<Vec<SearchResponse>, Whatever> {
        let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let socket = match UdpSocket::bind(local_addr).await {
            Ok(socket) => socket,
            Err(e) => whatever!("Unable to get a local address {:?}", e),
        };

        let local_addr = match socket.local_addr() {
            Ok(SocketAddr::V4(addr)) => addr,
            Ok(SocketAddr::V6(_addr)) => whatever!("Ipv6 socket adddress where IpV4 was expected"),
            Err(e) => whatever!("Unable to get local address {:?}", e),
        };

        let req = SearchRequest::udp_unicast(local_addr).packet();
        debug!("Sending search request {:0x?}", req);
        socket
            .send_to(&req, (SYSTEM_MULTICAST_ADDRESS, DISCOVERY_ENDPOINT_PORT))
            .await
            .expect("Unable to send request");

        let mut buffer = vec![0; 100];
        let mut responses = Vec::new();

        loop {
            select! {
                n_bytes = socket.recv(&mut buffer) => {
                    match n_bytes {
                        Ok(_n_bytes) => {
                            debug!("Search response {:0x?}", buffer);
                            let mut cursor = Cursor::new(buffer.as_slice());
                            let resp = SearchResponse::from_packet(&mut cursor)?;
                            debug!("Parsed search response {:0x?}", resp);
                            responses.push(resp);
                        },
                        Err(e) => {
                            whatever!("Unable to get response {:?}", e);
                        }
                    }
                },
                _ = tokio::time::sleep(timeout) => {
                     debug!("Search timeout received {} responses", responses.len());
                     break;
                }
            }
        }
        Ok(responses)
    }
}

pub fn parse_response(resp: Vec<u8>) -> Result<TunnelingResponse, Whatever> {
    let response_code = resp.get(2..4);
    if response_code.is_some() {
        if response_code == Some(&[0x04, 0x20]) {
            debug!("Received tunneling request");
            let mut resp_cursor = Cursor::new(resp.as_slice());
            let resp = TunnelingRequest::from_packet(&mut resp_cursor)?;
            debug!("Parsed tunneling request {:?}", resp);
            Ok(TunnelingResponse::TunnelingRequest(resp))
        } else if response_code == Some(&[0x04, 0x21]) {
            debug!("Received tunneling ack");
            let mut resp_cursor = Cursor::new(resp.as_slice());
            let resp = TunnelingAck::from_packet(&mut resp_cursor)?;
            debug!("Parsed tunneling ack {:?}", resp);
            Ok(TunnelingResponse::TunnelingAck(resp))
        } else if response_code == Some(&[0x04, 0x23]) {
            debug!("Received feature response");
            let mut resp_cursor = Cursor::new(resp.as_slice());
            let resp = FeatureResp::from_packet(&mut resp_cursor)?;
            debug!("Parsed feature response {:?}", resp);
            Ok(TunnelingResponse::FeatureResponse(resp))
        } else if response_code == Some(&[0x02, 0x0a]) {
            debug!("Received disconnection response");
            let mut resp_cursor = Cursor::new(resp.as_slice());
            let resp = DisconnectResponse::from_packet(&mut resp_cursor)?;
            debug!("Parsed disconnect response {:?}", resp);
            Ok(TunnelingResponse::DisconnectResponse(resp))
        } else if response_code == Some(&vec![0x02, 0x08]) {
            debug!("Received connection state response");
            let mut resp_cursor = Cursor::new(resp.as_slice());
            let resp = ConnectionstateResponse::from_packet(&mut resp_cursor)?;
            debug!("Parsed connection state response {:?}", resp);
            Ok(TunnelingResponse::ConnectionstateResponse(resp))
        } else if response_code == Some(&vec![0x02, 0x09]) {
            debug!("Received disconnect request");
            let mut resp_cursor = Cursor::new(resp.as_slice());
            let resp = DisconnectRequest::from_packet(&mut resp_cursor)?;
            debug!("Parsed disconnect request {:?}", resp);
            Ok(TunnelingResponse::DisconnectRequest(resp))
        } else {
            whatever!("Unknown response code {:?}", response_code);
        }
    } else {
        whatever!("Tunneling response without a valid code {:?}", response_code)
    }
}

// Connects to KNXIP device
//
pub(crate) async fn connect(socket: Arc<MyUdpSocket>) -> ConnectionResponse {
    loop {
        match try_connection(socket.clone()).await {
            Ok(connection) => return connection,
            Err(e) => {
                warn!("Unable to connect with KNXIP device, retry in 10 seconds {:?}", e);
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn try_connection(socket: Arc<MyUdpSocket>) -> Result<ConnectionResponse, Whatever> {
    let req = ConnectionRequest::tunnel().packet();
    debug!("Sending tunnel connection request {:0x?}", req);
    if let Err(e) = socket.send(&req).await {
        whatever!("Unable to send connection request {:?}", e);
    }

    let mut resp = vec![0; 100];
    if let Err(e) = timeout(Duration::from_secs(30), socket.recv(&mut resp)).await {
        whatever!("Target device does not respond {:?}", e);
    }
    debug!("Connection response {:0x?}", resp);

    let mut resp_cursor = Cursor::new(resp.as_slice());
    let connection = ConnectionResponse::from_packet(&mut resp_cursor)?;
    debug!("Parsed Connection response {:?}", connection);

    let connection_status = connection.get_status();
    ensure_whatever!(connection_status == 0, "Connection returned an error {:?}", connection_status);

    Ok(connection)
}

pub(crate) async fn handle_recv_from_knx_device(socket: Arc<MyUdpSocket>, from_knx_tx: Sender<CEMI>) -> TransportResult<String> {
    loop {
        let mut data = vec![0; 100];
        let count = socket.recv(&mut data).await.map_err(|e| format!("UPD Socket was closed {:?}", e))?;

        if count > 0 {
            let resp = parse_response(data)?;

            match resp {
                TunnelingResponse::TunnelingRequest(req) => {
                    let ack = TunnelingAck::new(req.communication_channel_id, req.sequence_nr, 0);
                    if let Err(e) = socket.send(&ack.packet()).await {
                        whatever!("Unable to send tunneling ack to knxip target {:?}", e);
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
                        Err(e) => whatever!("Unable to pass received request from knx device, {:?}", e),
                    };
                }
                TunnelingResponse::TunnelingAck(_) => {}
                TunnelingResponse::FeatureResponse(resp) => {
                    let ack = TunnelingAck::new(resp.communication_channel_id, resp.sequence_nr, 0);

                    if let Err(e) = socket.send(&ack.packet()).await {
                        whatever!("Unable to send tunneling ack to knxip target {:?}", e);
                    }
                }
                TunnelingResponse::ConnectionstateResponse(resp) => {
                    if resp.status != 0 {
                        warn!("Connection state response with error {}", resp.status);
                        whatever!("KNX device signaled a connection state error");
                    }
                }
                TunnelingResponse::DisconnectResponse(resp) => {
                    if resp.status == 0 {
                        info!("Successfully disconnected");
                    } else {
                        warn!("Unable to disconnect, status code {:?}", resp);
                    }
                    break Ok("KNX device disconnected by our will".into());
                }
                TunnelingResponse::DisconnectRequest(req) => {
                    let disconnect_resp = DisconnectResponse::from_disconnect_request(&req);
                    if let Err(e) = socket.send(&disconnect_resp.packet()).await {
                        warn!("Unable to send disconnect response to knxip target {:?}", e);
                    }
                    break Ok("KNX device requested disconnection".into());
                }
            }
        }
    }
}

pub struct UdpClient {
    timeout: Duration,
    transport: Arc<Mutex<UdpTransport>>,
}

impl UdpClient {
    pub async fn connect<A: ToSocketAddrs + std::fmt::Debug>(addr: A) -> Result<Self, Whatever> {
        let transport = Arc::new(Mutex::new(UdpTransport::connect(addr).await?));

        Ok(Self {
            transport,
            timeout: Duration::from_secs(10),
        })
    }

    pub async fn search(timeout: Duration) -> Result<Vec<SearchResponse>, Whatever> {
        let responses = UdpTransport::search(timeout).await?;
        Ok(responses)
    }

    fn get_read_timeout(&self) -> Duration {
        self.timeout.clone()
    }

    fn get_write_timeout(&self) -> Duration {
        self.timeout.clone()
    }

    pub async fn get_connection_status(&self) -> TransportResult<ConnectionstateResponse> {
        info!("Send connection heart beat");
        let transport = self.transport.lock().await;
        transport.get_connectionstate().await
    }

    pub async fn read_group_address_value(&self, addr: KnxAddress) -> TransportResult<Vec<u8>> {
        debug!("Read {:?}", addr);
        let expected_addr = addr.to_u16();
        let apdu = APDU::group_value_read();
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let transport = self.transport.lock().await;
        transport.tunnel_req(req.packet()).await?;
        let mut rx = transport.rx.lock().await;
        loop {
            match timeout(self.get_read_timeout(), rx.recv()).await {
                Ok(Some(cemi)) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                    let data_con = LDataCon::from_cemi(cemi);
                    debug!("Parsed confirmation cEMI {:?}", data_con);
                }
                Ok(Some(cemi)) if cemi.msg_code == CEMIMessageCode::LDataInd as u8 => {
                    let data_ind = LDataInd::from_cemi(cemi)?;
                    debug!("Parsed indication cEMI {:?}", data_ind);
                    if data_ind.l_data.dest == expected_addr {
                        return Ok(data_ind.value);
                    }
                }
                Ok(Some(cemi)) => warn!("Unknown cEMI message code {:?}", cemi.msg_code),
                Ok(None) => whatever!("No more data will be received from client"),
                Err(_) => whatever!("Request timed out"),
            }
        }
    }

    pub async fn flush(&self) -> Result<(), Whatever> {
        Ok(())
    }

    pub async fn write_group_address_value(&self, addr: KnxAddress, value: Vec<u8>) -> TransportResult<()> {
        debug!("Write {:?} to {:?}", value, addr);
        let apdu = APDU::group_value_write(value);
        let tpdu = TPDU::t_data_group(apdu);
        let req = LDataReqMessage::new(addr, tpdu);
        debug!("LDataReq {:?}", req);

        let transport = self.transport.lock().await;
        transport.tunnel_req(req.packet()).await?;
        debug!("Write request sent to bus");
        let mut rx = transport.rx.lock().await;
        loop {
            match timeout(self.get_write_timeout(), rx.recv()).await {
                Ok(Some(cemi)) if cemi.msg_code == CEMIMessageCode::LDataCon as u8 => {
                    let data_con = LDataCon::from_cemi(cemi);
                    debug!("Parsed confirmation cEMI {:?}", data_con);
                    return Ok(());
                }
                Ok(Some(cemi)) => whatever!("Unknown cEMI message code {:?}", cemi.msg_code),
                Ok(None) => whatever!("No more data will be received from client"),
                Err(_) => whatever!("Write request timed out"),
            }
        }
    }

    pub async fn disconnect(&self) -> Result<(), Whatever> {
        self.transport.lock().await.disconnect().await
    }
}

#[cfg(test)]
mod tests {
    use log::info;

    use super::*;

    #[tokio::test]
    async fn test_connect() {
        let _ = env_logger::try_init();
        let mock_server = UdpSocket::bind("0.0.0.0:0").await.expect("Unable to bind to local UDP port");
        let addr = mock_server.local_addr().expect("Mock server should have a valid local address");
        tokio::spawn(async move {
            let mut connection_req = vec![0; 100];
            let (_, peer) = mock_server.recv_from(&mut connection_req).await.expect("Unable to receive connection request");
            info!("[Mock server] Received {:02x?}", connection_req);
            let mock_resp = vec![
                0x06, 0x10, 0x02, 0x06, 0x00, 0x14, 0x08, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];
            mock_server.send_to(&mock_resp, peer).await.expect("Unable to send mock connection response");
            info!("[Mock server] Sended mock response");
        });

        let client = UdpTransport::connect(addr).await.expect("Unable to connect with mock server");
        assert_eq!(
            client.get_communication_channel_id().await.expect("To be able to get channel id"),
            8,
            "Communication channel id should be 8"
        );
    }

    #[tokio::test]
    async fn test_get_connectionstate() {
        let _ = env_logger::try_init();
        env_logger::try_init();
        let mock_server = UdpSocket::bind("0.0.0.0:0").await.expect("Unable to bind to local UDP port");
        let addr = mock_server.local_addr().expect("Mock server should have a valid local address");

        tokio::spawn(async move {
            let mut connection_req = vec![0; 100];
            let (_, peer) = mock_server.recv_from(&mut connection_req).await.expect("Unable to receive connection request");
            info!("[Mock server] Received {:02x?}", connection_req);
            let mock_resp = vec![
                0x06, 0x10, 0x02, 0x06, 0x00, 0x14, 0x08, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];
            mock_server.send_to(&mock_resp, peer).await.expect("Unable to send mock connection response");
            info!("[Mock server] Sended mock response");

            let mut connectionstate_req = vec![0; 100];
            let (_, peer) = mock_server
                .recv_from(&mut connectionstate_req)
                .await
                .expect("Unable to receive connection state request");
            let mut cursor = Cursor::new(connectionstate_req.as_slice());
            let req = ConnectionstateRequest::from_packet(&mut cursor).expect("Invalid connectionstate request");
            info!("[Mock server] Received connection state request {:?}", req);
            let connectionstate_resp = ConnectionstateResponse {
                communication_channel_id: req.communication_channel_id,
                status: 0,
            };
            mock_server
                .send_to(&connectionstate_resp.packet(), peer)
                .await
                .expect("Unable to respond to connection state request");
        });

        let client = UdpTransport::connect(addr).await.expect("Unable to connect with mock server");
        let state = client.get_connectionstate().await.expect("Should be able to request connectionstate");
        assert_eq!(
            state.communication_channel_id,
            client.get_communication_channel_id().await.expect("To be able to get channel id"),
            "Communication channel id should match client value"
        );
        assert_eq!(state.status, 0, "Connection state should be ok");
    }
}
