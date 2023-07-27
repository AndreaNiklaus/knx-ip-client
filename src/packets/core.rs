use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use snafu::{ensure_whatever, whatever, Whatever};
use std::{
    io::Cursor,
    net::{Ipv4Addr, SocketAddrV4},
};

use super::addresses::IndividualAddress;

// Connection request information
// 03.08.04 Tunneling section 4.4.3
//
pub const TUNNEL_LINKLAYER: u8 = 0x02;
pub const TUNNEL_RAW: u8 = 0x04;
pub const TUNNEL_BUSMONITOR: u8 = 0x80;
pub const E_NO_ERROR: u8 = 0x00;
pub const E_CONNECTION_TYPE: u8 = 0x22;
pub const E_CONNECTION_OPTION: u8 = 0x23;
pub const E_NO_MORE_CONNECTIONS: u8 = 0x24;
pub const E_TUNNELING_LAYER: u8 = 0x29;
#[derive(Debug)]
pub struct CRI {
    connection_type: u8,
}

impl CRI {
    pub fn tunnel_linklayer() -> Self {
        Self {
            connection_type: TUNNEL_LINKLAYER,
        }
    }
    pub fn tunnel_raw() -> Self {
        Self { connection_type: TUNNEL_RAW }
    }
    pub fn tunnel_busmonitor() -> Self {
        Self {
            connection_type: TUNNEL_BUSMONITOR,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        vec![4, 4, self.connection_type, 0]
    }
}

// Connection response data block
// 03.08.04 Tunneling section 4.4.4
#[derive(Debug)]
pub struct CRD {
    knx_individual_address: IndividualAddress,
}

impl CRD {
    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let size = match packet_reader.read_u8() {
            Ok(size) => {
                ensure_whatever!(size == 4, "Connection Response Data Block should have length 4 instead of {}", size);
                size
            }
            Err(e) => whatever!("Unable to read CRD packet size {:?}", e),
        };
        let tunnel_connection = match packet_reader.read_u8() {
            Ok(tunnel_connection) => {
                ensure_whatever!(
                    tunnel_connection == 4,
                    "Connection Response Data Block should have connection type 4 (TUNNELING) instead of {}",
                    tunnel_connection
                );
                tunnel_connection
            }
            Err(e) => whatever!("Unable to read CRD tunnel connection {:?}", e),
        };
        let knx_individual_address = match packet_reader.read_u16::<BigEndian>() {
            Ok(addr) => IndividualAddress::from_u16(addr),
            Err(e) => whatever!("Unable to read CRD KNX individual address {:?}", e),
        };
        Ok(Self { knx_individual_address })
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x04, 0x04];
        packet.write_u16::<BigEndian>(self.knx_individual_address.to_u16()).unwrap();
        packet
    }
}

// Connection request
// 03.08.02 Core section 7.8.1
//
#[derive(Debug)]
pub struct ConnectionRequest {
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

    pub fn busmonitor() -> Self {
        Self {
            control_endpoint: HPAI::udp(),
            data_endpoint: HPAI::udp(),
            cri: CRI::tunnel_busmonitor(),
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
#[derive(Debug)]
pub struct ConnectionResponse {
    communication_channel_id: u8,
    status: u8,
    data_endpoint: HPAI,
    crd: CRD,
}

impl ConnectionResponse {
    pub fn get_communication_channel_id(&self) -> u8 {
        self.communication_channel_id
    }
    pub fn get_data_endpoint(&self) -> HPAI {
        self.data_endpoint.clone()
    }
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        let version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let connect_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(connect_response) => {
                ensure_whatever!(
                    connect_response == 0x0206,
                    "Connect response should be 0x0206 instead of {:2X}",
                    connect_response
                );
                connect_response
            }
            Err(e) => whatever!("Unable to read Connect Response {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => {
                ensure_whatever!(size >= 8, "Packet size should greather than 8, received size {}", size);
                size
            }
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

        match status {
            E_CONNECTION_TYPE => {
                whatever!("Target KNX/IP device does not support requested connection type")
            }
            E_CONNECTION_OPTION => whatever!("Target KNX/IP device does not support one or more requested connection options"),
            E_NO_MORE_CONNECTIONS => {
                whatever!("No more connections available on target KNX/IP device")
            }
            E_TUNNELING_LAYER => {
                whatever!("Target KNX/IP device does not support requested tunneling layer")
            }
            _ => (),
        }

        let data_endpoint = HPAI::from_packet(&mut packet_reader)?;
        let crd = CRD::from_packet(&mut packet_reader)?;

        Ok(Self {
            communication_channel_id,
            status,
            data_endpoint,
            crd,
        })
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x02, 0x06, 0x08, self.communication_channel_id, self.status];
        packet.extend_from_slice(&self.data_endpoint.packet());
        packet.extend_from_slice(&self.crd.packet());
        packet
    }
}

// Connectionstate Request
// 03.08.02 Core section 7.8.3
//
#[derive(Debug)]
pub struct ConnectionstateRequest {
    pub communication_channel_id: u8,
    pub control_endpoint: HPAI,
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

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x0207, "Connect request should be 0x0207 instead of {:2X}", code);
            }
            Err(e) => whatever!("Unable to read Connectstate request code {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => size,
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        let _padding = match packet_reader.read_u8() {
            Ok(pad) => pad,
            Err(e) => whatever!("Unable to read padding data {:?}", e),
        };

        let control_endpoint = HPAI::from_packet(packet_reader)?;

        Ok(Self {
            communication_channel_id,
            control_endpoint,
        })
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
pub const E_CONNECTION_ID: u8 = 0x21;
pub const E_DATA_CONNECTION: u8 = 0x26;
pub const E_KNX_CONNECTION: u8 = 0x27;
#[derive(Debug)]
pub struct ConnectionstateResponse {
    pub communication_channel_id: u8,
    pub status: u8,
}

impl ConnectionstateResponse {
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        let version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let connectionstate_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x0208, "Connect response should be 0x0208 instead of {:2X}", code);
                code
            }
            Err(e) => whatever!("Unable to read Connectstate Response {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => {
                ensure_whatever!(size == 8, "Packet size should be 8, received size {}", size);
                size
            }
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

    pub fn packet(&self) -> Vec<u8> {
        let packet = vec![0x06, 0x10, 0x02, 0x08, 0x00, 0x08, self.communication_channel_id, self.status];
        packet
    }
}

// Disconnect request
// 03.08.02 Core section 7.8.5
//
#[derive(Debug)]
pub struct DisconnectRequest {
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
pub struct DisconnectResponse {
    pub communication_channel_id: u8,
    pub status: u8,
}

impl DisconnectResponse {
    pub fn from_packet(mut packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        let version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let connectionstate_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x020a, "Disconnect response should be 0x020A instead of {:2X}", code);
                code
            }
            Err(e) => whatever!("Unable to read Disconnect Response {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => {
                ensure_whatever!(size == 8, "Packet size should be 8, received size {}", size);
                size
            }
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
pub const HPAI_IPV4_UDP: u8 = 1;
pub const HPAI_IPV4_TCP: u8 = 2;
#[derive(Debug, Clone)]
pub struct HPAI {
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
            }
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
