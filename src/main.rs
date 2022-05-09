use std::{net::{UdpSocket, Ipv4Addr, SocketAddrV4}, io::{Cursor, Read}, time::Duration, convert::{TryFrom, TryInto}, fmt};

use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use snafu::{Whatever, whatever};
use snafu::prelude::*;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Unable to get free port");
    socket.set_read_timeout(Some(Duration::from_secs(1))).expect("Unable to set read timeout");
    socket.connect("192.168.1.149:3671").expect("Unable to connect to knx ip server");

    for i in 0..1 {
        let req = ConnectionstateRequest::new(i, HPAI::udp()).packet();
        println!("Request status for connection {}", i);
        socket.send(&req).expect("Unable to send request");

        let mut resp = vec![0; 100];
        socket.recv(&mut resp).expect("Unable to get response");
        let mut resp_cursor = Cursor::new(resp.as_slice());
        match ConnectionstateResponse::from_packet(&mut resp_cursor) {
            Ok(status) => {
                let mut to_close = true;
                if status.status == E_NO_ERROR {
                    println!("Connection {} is ok", status.communication_channel_id);
                } else if status.status == E_CONNECTION_ID {
                    println!("No connection foud with id {}", i);
                    to_close = false;
                } else if status.status == E_DATA_CONNECTION {
                    println!("Connection with id {} as an error concerning the data connection", i);
                } else if status.status == E_KNX_CONNECTION {
                    println!("Connection with id {} as an error concerning the knx connection", i);
                }

                if to_close {
                    let req = DisconnectRequest::new(i, HPAI::udp()).packet();
                    println!("Request dosconnect for connection {}", i);
                    socket.send(&req).expect("Unable to send request");

                    let mut resp = vec![0; 100];
                    socket.recv(&mut resp).expect("Unable to get response");
                    let mut resp_cursor = Cursor::new(resp.as_slice());

                    match DisconnectResponse::from_packet(&mut resp_cursor) {
                        Ok(resp) => {
                            println!("Disconnect response status {}", resp.status);
                        },
                        Err(e) => eprintln!("Unable to request disconnection for id {}, {:?}", i, e),
                    }
                }
            },
            Err(e) => eprintln!("Unable to get status for connection {}, {:?}", i, e),
        };
    }

    let req = vec![0x06u8, 0x10, 0x02, 0x03, 0x00, 0x0e, 0x08, 0x01, 0, 0, 0, 0, 0, 0];

    println!("Request: {:02x?}", req);
    socket.send(&req).expect("Unable to send request");

    let mut resp = vec![0; 100];
    socket.recv(&mut resp).expect("Unable to get response");

    println!("Response: {:02x?}", resp);

    let mut crs = Cursor::new(resp);
    let header_size = crs.read_u8();
    let protocol_version = crs.read_u8();
    let service_id = crs.read_u16::<BigEndian>();
    let total_size = crs.read_u16::<BigEndian>();
    // let mut dibs = Vec::new();

    loop {
        if let Ok(dib_size) = crs.read_u8() {
            if dib_size == 0 {
                break;
            }
            let dib_type = crs.read_u8().unwrap();
            println!("Dib type {} with size {}", dib_type, dib_size);
            let mut dib_data = vec![0; (dib_size - 2) as usize];
            crs.read(&mut dib_data).unwrap();
            println!("{:?}", dib_data);
            let mut dib_data = Cursor::new(dib_data);

            if dib_type == 1 {
                // Device Info
                let medium = dib_data.read_u8();
                let device_status = dib_data.read_u8();
                let individual_addr = dib_data.read_u16::<BigEndian>();
                let project_id = dib_data.read_u16::<BigEndian>();
                let mut serial_nr = vec![0; 6];
                dib_data.read(&mut serial_nr);
                let mut multicast_addr = vec![0; 4];
                dib_data.read(&mut multicast_addr);
                let mut mac_addr = vec![0; 6];
                dib_data.read(&mut mac_addr);
                let mut name = vec![0; 30];
                dib_data.read(&mut name);
                println!("Friendly name: {:?}", name);
                let name = std::str::from_utf8(&name);
                println!("Friendly name: {:?}", name);
            } else if dib_type == 2 {
                // Supported services families
                let count = (dib_size - 2) / 2;
                for _ in 0..count {
                    // 2 -> Core
                    // 3 -> Device Management
                    // 4 -> Tunneling
                    // 5 -> Routing
                    // 6 -> Remote logging
                    // 7 -> Remote configuration and diagnostics
                    // 8 -> Object server
                    let family = dib_data.read_u8();
                    let version = dib_data.read_u8();
                    println!("Family {:?} version {:?}", family, version);
                }
            } else if dib_type == 3 {
                // Ip configuration
            } else if dib_type == 4 {
                // Current ip configuration
            } else if dib_type == 5 {
                // KNX addresses
            }
            // dibs.push((dib_type, dib_data));
        }
    }

    let req = ConnectionRequest::tunnel();
    println!("Connection Request: {:?}", req);
    let req = req.packet();
    println!("Request: {:02x?}", req);
    socket.send(&req).expect("Unable to send request");

    let mut resp = vec![0; 100];
    socket.recv(&mut resp).expect("Unable to get response");

    println!("Response: {:02x?}", resp);
    let mut resp_cursor = Cursor::new(resp.as_slice());
    let connection = ConnectionResponse::from_packet(&mut resp_cursor).expect("Unable to parse connection response");
    println!("Parsed resp: {:?}", connection);

    let status_request = ConnectionstateRequest::from_connection_response(&connection);
    println!("ConnectionstateRequest: {:?}", status_request);
    let status_request = status_request.packet();
    println!("ConnectionstateRequest: {:02x?}", status_request);
    socket.send(&status_request).expect("Unable to send request");

    let mut resp = vec![0; 100];
    socket.recv(&mut resp).expect("Unable to get response");

    let mut resp_cursor = Cursor::new(resp.as_slice());
    let parsed_status = ConnectionstateResponse::from_packet(&mut resp_cursor);
    println!("ConnectionstateResponse: {:?}", parsed_status);

    // Read group value
    //
    let req = LDataReqMessage::new(KnxAddress::group_3_level(5, 1, 2));
    println!("LDataReq {:?}", req);

    let tunneled_req = TunnelingRequest::new(connection.communication_channel_id, 0, req.packet());
    println!("TunnelingRequest {:?}", tunneled_req);
    let req = tunneled_req.packet();
    println!("Read Group Value request: {:02x?}", req);
    socket.send(&req).expect("Unable to send request");

    let mut resp = vec![0; 100];
    match socket.recv(&mut resp) {
        Ok(len) => len,
        Err(_) => {
            println!("Resend last packet");
            socket.send(&req).expect("Unable to resend request");
            match socket.recv(&mut resp) {
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
    socket.recv(&mut resp).expect("Unable to get response");
    println!("Read Group Value response: {:02x?}", resp);
    let mut resp_cursor = Cursor::new(resp.as_slice());
    match TunnelingRequest::from_packet(&mut resp_cursor) {
        Ok(parsed_resp) => {
            println!("Read Group Value response: {:?}", parsed_resp);
            let mut cemi_cursor = Cursor::new(parsed_resp.cemi.as_slice());
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

    // Disconnect
    //
    let req = DisconnectRequest::new(connection.communication_channel_id, connection.data_endpoint).packet();
    println!("Request dosconnect for connection {}", connection.communication_channel_id);
    socket.send(&req).expect("Unable to send request");

    let mut resp = vec![0; 100];
    socket.recv(&mut resp).expect("Unable to get response");
    let mut resp_cursor = Cursor::new(resp.as_slice());

    match DisconnectResponse::from_packet(&mut resp_cursor) {
        Ok(resp) => {
            println!("Disconnect response status {}", resp.status);
        },
        Err(e) => eprintln!("Unable to request disconnection {:?}", e),
    }
}

// Connection request
// 03.08.02 Core section 7.8.1
//
#[derive(Debug)]
struct ConnectionRequest {
    control_endpoint: HPAI,
    data_endpoint: HPAI,
    cri: CRI,
}

impl ConnectionRequest {
    pub fn tunnel() -> Self {
        Self {
            control_endpoint: HPAI::udp(),
            data_endpoint: HPAI::udp(),
            cri: CRI::tunnel_linklayer(),
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![6, 0x10, 2, 5]; // Header
        let mut control_endpoint_packet = self.control_endpoint.packet();
        let mut data_endpoint_packet = self.data_endpoint.packet();
        let mut cri_packet = self.cri.packet();

        let mut packet_size = 6;
        packet_size += control_endpoint_packet.len();
        packet_size += data_endpoint_packet.len();
        packet_size += cri_packet.len();

        packet.write_u16::<BigEndian>(packet_size as u16).unwrap();
        packet.append(&mut control_endpoint_packet);
        packet.append(&mut data_endpoint_packet);
        packet.append(&mut cri_packet);

        packet
    }
}

// Connection response
// 03.08.02 Core section 7.8.2
//
const E_CONNECTION_TYPE: u8 = 0x22;
const E_CONNECTION_OPTION: u8 = 0x23;
const E_NO_MORE_CONNECTIONS: u8 = 0x24;
#[derive(Debug)]
struct ConnectionResponse {
    communication_channel_id: u8,
    status: u8,
    data_endpoint: HPAI,
    crd: CRD,
}

impl ConnectionResponse {
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            },
            Err(e) => whatever!("Unable to read header size {:?}", e)
        };

        let version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            },
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let connect_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(connect_response) => {
                ensure_whatever!(connect_response == 0x0206, "Connect response should be 0x0206 instead of {:2X}", connect_response);
                connect_response
            },
            Err(e) => whatever!("Unable to read Connect Response {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => {
                ensure_whatever!(size > 8, "Packet size should greather than 8, received size {}", size);
                size
            },
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read Communication Channel Id {:?}", e),
        };

        let status = match packet_reader.read_u8() {
            Ok(status) => status,
            Err(e) => whatever!("Unable to read status {:?}", e),
        };

        let data_endpoint = HPAI::from_packet(&mut packet_reader)?;
        let crd = CRD::from_packet(&mut packet_reader)?;

        Ok(Self {
            communication_channel_id,
            status,
            data_endpoint,
            crd
        })
    }
}

// Connection response data block
// 03.08.04 Tunneling section 4.4.4
#[derive(Debug)]
struct CRD {
    knx_individual_address: IndividualAddress,
}

impl CRD {
    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let size = match packet_reader.read_u8() {
            Ok(size) => {
                ensure_whatever!(size == 4, "Connection Response Data Block should have length 4 instead of {}", size);
                size
            },
            Err(e) => whatever!("Unable to read CRD packet size {:?}", e)
        };
        let tunnel_connection = match packet_reader.read_u8() {
            Ok(tunnel_connection) => {
                ensure_whatever!(tunnel_connection == 4, "Connection Response Data Block should have connection type 4 (TUNNELING) instead of {}", tunnel_connection);
                tunnel_connection
            },
            Err(e) => whatever!("Unable to read CRD tunnel connection {:?}", e)
        };
        let knx_individual_address = match packet_reader.read_u16::<BigEndian>() {
            Ok(addr) => IndividualAddress::from_u16(addr),
            Err(e) => whatever!("Unable to read CRD KNX individual address {:?}", e)
        };
        Ok(Self {
            knx_individual_address
        })
    }
}

// Connection request information
// 03.08.04 Tunneling section 4.4.3
//
const TUNNEL_LINKLAYER: u8 = 0x02;
const TUNNEL_RAW: u8 = 0x04;
const TUNNEL_BUSMONITOR: u8 = 0x80;
const E_NO_ERROR: u8 = 0x00;
const E_TUNNELING_LAYER: u8 = 0x29;
#[derive(Debug)]
struct CRI {
    connection_type: u8,
}

impl CRI {
    pub fn tunnel_linklayer() -> Self {
        Self {
            connection_type: TUNNEL_LINKLAYER
        }
    }
    pub fn tunnel_raw() -> Self {
        Self {
            connection_type: TUNNEL_RAW
        }
    }
    pub fn tunnel_busmonitor() -> Self {
        Self {
            connection_type: TUNNEL_BUSMONITOR
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        vec![4, 4, self.connection_type, 0]
    }
}

// Connectionstate Request
// 03.08.02 Core section 7.8.3
//
#[derive(Debug)]
struct ConnectionstateRequest {
    communication_channel_id: u8,
    control_endpoint: HPAI,
}

impl ConnectionstateRequest {
    pub fn new(communication_channel_id: u8, control_endpoint: HPAI) -> Self {
        Self {
            communication_channel_id,
            control_endpoint,
        }
    }

    pub fn from_connection_response(resp: &ConnectionResponse) -> Self {
        Self {
            communication_channel_id: resp.communication_channel_id,
            control_endpoint: resp.data_endpoint.clone(),
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x02, 0x07];
        let mut control_endpoint_packet = self.control_endpoint.packet();
        let size = packet.len() + 4 + control_endpoint_packet.len();
        packet.write_u16::<BigEndian>(size as u16).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(0).unwrap();

        packet.append(&mut control_endpoint_packet);

        packet
    }
}

// Connectionstate Response
// 03.08.02 Core section 7.8.4
//
const E_CONNECTION_ID: u8 = 0x21;
const E_DATA_CONNECTION: u8 = 0x26;
const E_KNX_CONNECTION: u8 = 0x27;
#[derive(Debug)]
struct ConnectionstateResponse {
    communication_channel_id: u8,
    status: u8,
}

impl ConnectionstateResponse {
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            },
            Err(e) => whatever!("Unable to read header size {:?}", e)
        };

        let version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            },
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let connectionstate_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x0208, "Connect response should be 0x0208 instead of {:2X}", code);
                code
            },
            Err(e) => whatever!("Unable to read Connectstate Response {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => {
                ensure_whatever!(size == 8, "Packet size should be 8, received size {}", size);
                size
            },
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read Communication Channel Id {:?}", e),
        };

        let status = match packet_reader.read_u8() {
            Ok(status) => status,
            Err(e) => whatever!("Unable to read status {:?}", e),
        };

        Ok(Self {
            communication_channel_id,
            status,
        })
    }
}

// Disconnect request
// 03.08.02 Core section 7.8.5
//
#[derive(Debug)]
struct DisconnectRequest {
    communication_channel_id: u8,
    control_endpoint: HPAI,
}

impl DisconnectRequest {
    pub fn new(communication_channel_id: u8, control_endpoint: HPAI) -> Self {
        Self {
            communication_channel_id,
            control_endpoint,
        }
    }
    pub fn from_connection_response(resp: &ConnectionResponse) -> Self {
        Self {
            communication_channel_id: resp.communication_channel_id,
            control_endpoint: resp.data_endpoint.clone(),
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x02, 0x09];
        let mut control_endpoint_packet = self.control_endpoint.packet();
        let size = packet.len() + 4 + control_endpoint_packet.len();
        packet.write_u16::<BigEndian>(size as u16).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(0).unwrap();

        packet.append(&mut control_endpoint_packet);

        packet
    }
}


// Disconnect Response
// 03.08.02 Core section 7.8.6
//
#[derive(Debug)]
struct DisconnectResponse {
    communication_channel_id: u8,
    status: u8,
}

impl DisconnectResponse {
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            },
            Err(e) => whatever!("Unable to read header size {:?}", e)
        };

        let version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            },
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let connectionstate_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x020a, "Disconnect response should be 0x020A instead of {:2X}", code);
                code
            },
            Err(e) => whatever!("Unable to read Disconnect Response {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => {
                ensure_whatever!(size == 8, "Packet size should be 8, received size {}", size);
                size
            },
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read Communication Channel Id {:?}", e),
        };

        let status = match packet_reader.read_u8() {
            Ok(status) => status,
            Err(e) => whatever!("Unable to read status {:?}", e),
        };

        Ok(Self {
            communication_channel_id,
            status,
        })
    }
}
// Host Protocol Address Information
// 03.08.02 Core section 8.6.2
//
const HPAI_IPV4_UDP: u8 = 1;
const HPAI_IPV4_TCP: u8 = 2;
#[derive(Debug, Clone)]
struct HPAI {
    host_protocol_code: u8,
    address: SocketAddrV4,
}

impl HPAI {
    pub fn udp() -> Self {
        Self {
            host_protocol_code: HPAI_IPV4_UDP,
            address: "0.0.0.0:0".parse().unwrap(),
        }
    }

    pub fn tcp() -> Self {
        Self {
            host_protocol_code: HPAI_IPV4_TCP,
            address: "0.0.0.0:0".parse().unwrap(),
        }
    }

    pub fn set_addr(&mut self, address: SocketAddrV4) {
        self.address = address;
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.write_u8(8).unwrap();
        packet.write_u8(self.host_protocol_code).unwrap();
        let ip = self.address.ip().octets();
        packet.extend_from_slice(&ip);
        packet.write_u16::<BigEndian>(self.address.port()).unwrap();
        packet
    }

    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let size = match packet_reader.read_u8() {
            Ok(size) => {
                ensure_whatever!(size == 8, "HPAI size must be 8 instead of {}", size);
                size
            },
            Err(e) => whatever!("Unable to read HPAI size {:?}", e),
        };

        let host_protocol_code = match packet_reader.read_u8() {
            Ok(code) => code,
            Err(e) => whatever!("Unable to read HPAI host protocol code {:?}", e),
        };

        let ip_1 = match packet_reader.read_u8() {
            Ok(ip) => ip,
            Err(e) => whatever!("Unable to read HPAI IP part 1 {:?}", e),
        };
        let ip_2 = match packet_reader.read_u8() {
            Ok(ip) => ip,
            Err(e) => whatever!("Unable to read HPAI IP part 2 {:?}", e),
        };
        let ip_3 = match packet_reader.read_u8() {
            Ok(ip) => ip,
            Err(e) => whatever!("Unable to read HPAI IP part 3 {:?}", e),
        };
        let ip_4 = match packet_reader.read_u8() {
            Ok(ip) => ip,
            Err(e) => whatever!("Unable to read HPAI IP part 4 {:?}", e),
        };

        let port = match packet_reader.read_u16::<BigEndian>() {
            Ok(port) => port,
            Err(e) => whatever!("Unable to read HPAI IP Port {:?}", e),
        };

        Ok(Self {
            host_protocol_code,
            address: SocketAddrV4::new(Ipv4Addr::new(ip_1, ip_2, ip_3, ip_4), port),
        })
    }
}

// Tunneling request
// 03.08.04 Tunneling section 4.4.6
//
#[derive(Debug)]
struct TunnelingRequest {
    communication_channel_id: u8,
    sequence_nr: u8,
    cemi: Vec<u8>
}

impl TunnelingRequest {
    pub fn new(communication_channel_id: u8, sequence_nr: u8, cemi: Vec<u8>) -> Self {
        Self {
            communication_channel_id,
            sequence_nr,
            cemi,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x04, 0x20];
        packet.write_u16::<BigEndian>(10 + self.cemi.len() as u16).unwrap();
        packet.write_u8(4).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(self.sequence_nr).unwrap();
        packet.write_u8(0).unwrap();
        packet.extend(&self.cemi);
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        match packet_reader.read_u16::<BigEndian>() {
            Ok(header) => {
                ensure_whatever!(header == 0x0610, "Header should be 0x0610 instead of {}", header);
            },
            Err(e) => whatever!("Unable to read header {:?}", e)
        };

        match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x0420, "Code should be 0x0420 instead of {}", code);
            },
            Err(e) => whatever!("Unable to read code {:?}", e)
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => size,
            Err(e) => whatever!("Unable to read packet size {:?}", e)
        };

        match packet_reader.read_u8() {
            Ok(size) => {
                ensure_whatever!(size == 0x04, "Size should be 0x04 instead of {}", size);
            },
            Err(e) => whatever!("Unable to read message code {:?}", e)
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e)
        };

        let sequence_nr = match packet_reader.read_u8() {
            Ok(sequence_nr) => sequence_nr,
            Err(e) => whatever!("Unable to read sequence number {:?}", e)
        };

        match packet_reader.read_u8() {
            Ok(_) => (),
            Err(e) => whatever!("Unable to read padding {:?}", e)
        };

        let mut cemi = vec![0; size as usize - 10];
        if let Err(e) = packet_reader.read(&mut cemi) {
            whatever!("Unable to read cemi part {:?}", e);
        }

        Ok(Self {
            communication_channel_id,
            sequence_nr,
            cemi,
        })
    }
}

// cEMI
//
#[derive(Debug)]
struct CEMI {
    msg_code: u8,
    additional_infos: Vec<CEMIAdditionalInfo>,
    service_info: Vec<u8>,
}

impl CEMI {
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let msg_code = match packet_reader.read_u8() {
            Ok(code) => code,
            Err(e) => whatever!("Unable to read message code {:?}", e),
        };

        let additional_infos_size = match packet_reader.read_u8() {
            Ok(size) => size,
            Err(e) => whatever!("Unable to read addition infos size {:?}", e),
        };

        let mut additional_infos = Vec::new();
        let mut position = 0;
        while position < additional_infos_size {
            let additional_info_type: CEMIAdditionalInfoType = match packet_reader.read_u8() {
                Ok(info_type) => match info_type.try_into() {
                    Ok(t) => t,
                    Err(e) => whatever!("Unknown additional info type")
                },
                Err(e) => whatever!("Unable to read addition info type {:?}", e),
            };
            let additional_info_size = match packet_reader.read_u8() {
                Ok(size) => size,
                Err(e) => whatever!("Unable to read addition info size {:?}", e),
            };

            let mut additional_info = vec![0; additional_info_size as usize];
            if let Err(e) = packet_reader.read(&mut additional_info) {
                whatever!("Unable to read additional info {:?}", e);
            }

            additional_infos.push(CEMIAdditionalInfo {
                info_type: additional_info_type,
                value: additional_info,
            });
            position += additional_info_size + 2;
        }

        let mut service_info = Vec::new();
        if let Err(e) = packet_reader.read_to_end(&mut service_info) {
            whatever!("Unable to read service information {:?}", e);
        }

        Ok(Self{
            msg_code,
            additional_infos,
            service_info,
        })
    }
}

#[derive(Copy, Clone)]
#[repr(u8)]
enum CEMIMessageCode {
    LBusmodInd = 0x2b, // NL
    LDataReq = 0x11, // DLL
    LDataCon = 0x2e, // NL
    LDataInd = 0x29, // NL

    LRawReq = 0x10, // DLL
    LRawInd = 0x2d, // NL
    LRawCon = 0x2f, // NL
    LPollDataReq = 0x13, // DLL
    LPollDataCon = 0x25, // NL

    TDataConnectedReq = 0x41,
    TDataConnectedInd = 0x89,
    TDataIndividualReq = 0x4a,
    TDataIndividualInd = 0x94,

    MPropReadReq = 0xFC, // CEMI Management Server
    MPropReadCon = 0xfb, // CEMI Management Client
    MPropWriteReq = 0xf6, // CEMI Management Client
    MPropWriteCon = 0xf5, // CEMI Management Server
    MPropInfoInd = 0xf7, // CEMI Management Server
    MFuncPropCommandReq = 0xf8, // CEMI Management Client
    MFuncPropStateReq = 0xf9, // CEMI Management Client
    MFuncPropCommandCon = 0xfa, // CEMI Management Server
    MResetReq = 0xf1, // CEMI Management Client
    MResetInd = 0xf0, // CEMI Management Server
}

#[derive(Debug)]
enum CEMIAdditionalInfoType {
    PLMediumInfo = 0x01,
    RFMediumInfo = 0x02,
    BusmonitorStatusInfo = 0x03,
    TimestampRelative = 0x04,
    TimeDelayUnitlSending = 0x05,
    ExtendedRelativeTime = 0x06,
    BiBatInfo = 0x07,
    RFMultiInfo = 0x08,
    PreambleAndPostamble = 0x09,
    RFFastAckInfo = 0x0a,
    ManufacturerSpecificData = 0xfe,
}

#[derive(Debug)]
struct CEMIAdditionalInfo {
    info_type: CEMIAdditionalInfoType,
    value: Vec<u8>,
}

impl TryFrom<u8> for CEMIAdditionalInfoType {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == CEMIAdditionalInfoType::PLMediumInfo as u8 => Ok(CEMIAdditionalInfoType::PLMediumInfo),
            x if x == CEMIAdditionalInfoType::RFMediumInfo as u8 => Ok(CEMIAdditionalInfoType::RFMediumInfo),
            x if x == CEMIAdditionalInfoType::BusmonitorStatusInfo as u8 => Ok(CEMIAdditionalInfoType::BusmonitorStatusInfo),
            x if x == CEMIAdditionalInfoType::TimestampRelative as u8 => Ok(CEMIAdditionalInfoType::TimestampRelative),
            x if x == CEMIAdditionalInfoType::TimeDelayUnitlSending as u8 => Ok(CEMIAdditionalInfoType::TimeDelayUnitlSending),
            x if x == CEMIAdditionalInfoType::ExtendedRelativeTime as u8 => Ok(CEMIAdditionalInfoType::ExtendedRelativeTime),
            x if x == CEMIAdditionalInfoType::BiBatInfo as u8 => Ok(CEMIAdditionalInfoType::BiBatInfo),
            x if x == CEMIAdditionalInfoType::RFMultiInfo as u8 => Ok(CEMIAdditionalInfoType::RFMultiInfo),
            x if x == CEMIAdditionalInfoType::PreambleAndPostamble as u8 => Ok(CEMIAdditionalInfoType::PreambleAndPostamble),
            x if x == CEMIAdditionalInfoType::RFFastAckInfo as u8 => Ok(CEMIAdditionalInfoType::RFFastAckInfo),
            x if x == CEMIAdditionalInfoType::ManufacturerSpecificData as u8 => Ok(CEMIAdditionalInfoType::ManufacturerSpecificData),
            _ => Err(())
        }
    }
}

#[derive(Debug)]
struct LData {
    src: u16,
    dest: u16,
    frame_type: bool,
    repetition: bool,
    system_broadcast: bool,
    ack_request: bool,
}

struct LDataReq {
    cemi: CEMI,
    l_data: LData,
}

#[derive(Debug)]
struct LDataCon {
    cemi: CEMI,
    l_data: LData,
    confirm: bool,
}

impl LDataCon {
    pub fn from_cemi(cemi: CEMI) -> Result<Self, Whatever> {
        let mut reader = Cursor::new(cemi.service_info.as_slice());
        let control1 = match reader.read_u8() {
            Ok(control1) => control1,
            Err(e) => whatever!("Unable to read control 1 byte {:?}", e),
        };
        let control2 = match reader.read_u8() {
            Ok(control2) => control2,
            Err(e) => whatever!("Unable to read control 2 byte {:?}", e),
        };
        let src = match reader.read_u16::<BigEndian>() {
            Ok(src) => src,
            Err(e) => whatever!("Unable to read source address {:?}", e),
        };
        let dest = match reader.read_u16::<BigEndian>() {
            Ok(dest) => dest,
            Err(e) => whatever!("Unable to read destination address {:?}", e),
        };

        let frame_type = (control1 & 0x80) > 0;
        let repetition = (control1 & (1 << 5)) > 0;
        let system_broadcast = (control1 & (1 << 4)) > 0;
        let ack_request = (control1 & (1 << 1)) > 0;
        let confirm = (control1 & 1) == 0;

        Ok(Self {
            cemi,
            l_data: LData {
                src,
                dest,
                frame_type,
                repetition,
                system_broadcast,
                ack_request,
            },
            confirm,
        })
    }
}

// L_Data request message
// 03.06.03 EMI IMI section 4.1.5.3.3
#[derive(Debug)]
struct LDataReqMessage {
    priority: u8,
    dest_address: KnxAddress,
}

impl LDataReqMessage {
    pub fn new(dest_address: KnxAddress) -> Self {
        Self {
            priority: 0b11,
            dest_address,
        }
    }

    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut control = 0u8;
        control |= 1 << 7; // Frame type standard
        control |= 1 << 5; // No repetition on error
        control |= 1 << 4; // Domain broadcast
        control |= (self.priority & 0x3) << 2;

        let control2 = 0xe0u8;
        let mut packet = vec![CEMIMessageCode::LDataReq as u8, 0, control, control2, 0, 0];

        // packet.write_u16::<BigEndian>(0).unwrap();
        packet.write_u16::<BigEndian>(self.dest_address.to_u16()).unwrap();

        packet.write_u8(1).unwrap(); // Count of APCI values
        packet.write_u8(0).unwrap(); // TPCI
        packet.write_u8(0).unwrap(); // APCI GroupValueRead

        packet
    }
}

// KNX Address
//
#[derive(Debug)]
enum KnxAddress {
    Individual(IndividualAddress),
    Group3Level(Group3LevelAddress),
    Group2Level(Group2LevelAddress),
    Group1Level(Group1LevelAddress),
}

impl KnxAddress {
    pub fn individual(area: u8, line: u8, address: u8) -> Self {
        Self::Individual(IndividualAddress {
            area,
            line,
            address,
        })
    }

    pub fn group_3_level(main: u8, middle: u8, sub: u8) -> Self {
        Self::Group3Level(Group3LevelAddress {
            main,
            middle,
            sub,
        })
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Individual(a) => a.to_u16(),
            Self::Group3Level(a) => a.to_u16(),
            Self::Group2Level(a) => a.to_u16(),
            Self::Group1Level(a) => a.to_u16(),
        }
    }
}

struct IndividualAddress {
    area: u8,
    line: u8,
    address: u8,
}

impl IndividualAddress {
    pub fn to_u16(&self) -> u16 {
        let mut addr = 0u16;
        addr |= (self.area as u16) << 12 as u16;
        addr |= (self.line as u16) << 8 as u16;
        addr |= (self.address) as u16;

        addr
    }

    pub fn from_u16(addr: u16) -> Self {
        let area = (0xf000 & addr) >> 12;
        let line = (0x0f00 & addr) >> 8;
        let address = 0x00ff & addr;

        Self {
            area: area as u8,
            line: line as u8,
            address: address as u8,
        }
    }
}

impl fmt::Debug for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.area, self.line, self.address)
    }
}

struct Group3LevelAddress {
    main: u8,
    middle: u8,
    sub: u8,
}

impl fmt::Debug for Group3LevelAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.main, self.middle, self.sub)
    }
}

impl Group3LevelAddress {
    pub fn to_u16(&self) -> u16 {
        let mut addr = 0u16;
        addr |= (self.main as u16) << 11 as u16;
        addr |= (self.middle as u16) << 8 as u16;
        addr |= (self.sub) as u16;

        addr
    }
}

struct Group2LevelAddress {
    main: u8,
    sub: u8,
}

impl fmt::Debug for Group2LevelAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.main, self.sub)
    }
}

impl Group2LevelAddress {
    pub fn to_u16(&self) -> u16 {
        let mut addr = 0u16;
        addr |= (self.main as u16) << 8 as u16;
        addr |= (self.sub) as u16;

        addr
    }
}

struct Group1LevelAddress {
    main: u16,
}

impl fmt::Debug for Group1LevelAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.main)
    }
}

impl Group1LevelAddress {
    pub fn to_u16(&self) -> u16 {
        self.main
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_request() {
        let req = ConnectionRequest::tunnel().packet();

        assert_eq!(req, vec![0x06, 0x10, 0x02, 0x05, 0x00, 0x1a, 0x08, 0x01, 0, 0, 0, 0, 0, 0, 0x08, 0x01, 0, 0, 0, 0, 0, 0, 0x04, 0x04, 0x02, 0], "Wrong connection request packet");
    }

    #[test]
    fn connectionstate_request() {
        let req = ConnectionstateRequest::new(8, HPAI::udp()).packet();

        assert_eq!(req, vec![0x06, 0x10, 0x02, 0x07, 0x00, 0x10, 0x08, 0x00, 8, 1, 0, 0, 0, 0, 0, 0], "Wrong connection state request packet");
    }

    #[test]
    fn disconnect_request() {
        let req = DisconnectRequest::new(8, HPAI::udp()).packet();

        assert_eq!(req, vec![0x06, 0x10, 0x02, 0x09, 0x00, 0x10, 0x08, 0x00, 8, 1, 0, 0, 0, 0, 0, 0], "Wrong connection state request packet");
    }

    #[test]
    fn knx_group_3_level_address() {
        let main_group = Group3LevelAddress {
            main: 8,
            middle: 0,
            sub: 0,
        };
        assert_eq!(main_group.to_u16(), 0x4000, "Wrong encoding of main group");

        let mid_group = Group3LevelAddress {
            main: 0,
            middle: 7,
            sub: 0,
        };
        assert_eq!(mid_group.to_u16(), 0x0700, "Wrong encoding of mid group");

        let address_group = Group3LevelAddress {
            main: 0,
            middle: 0,
            sub: 6,
        };
        assert_eq!(address_group.to_u16(), 0x0006, "Wrong encoding of address");

        let address_group = Group3LevelAddress {
            main: 1,
            middle: 1,
            sub: 1,
        };
        assert_eq!(address_group.to_u16(), 0x0901, "Wrong encoding of address");
    }

    #[test]
    fn read_group_value() {
        let req = LDataReqMessage::new(KnxAddress::group_3_level(1, 1, 1));

        let tunneled_req = TunnelingRequest::new(0x17, 4, req.packet());
        let req = tunneled_req.packet();

        assert_eq!(req, [0x06, 0x10, 0x04, 0x20, 0, 0x15, 0x04, 0x17, 0x04, 0, 0x11, 0, 0xbc, 0xe0, 0, 0, 0x09, 0x01, 0x01, 0, 0], "Wrong read group request packet");
    }
}
