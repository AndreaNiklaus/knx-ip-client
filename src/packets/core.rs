use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use encoding::all::ISO_8859_1;
use encoding::{DecoderTrap, EncoderTrap, Encoding};
use snafu::{ensure_whatever, whatever, ResultExt, Whatever};
use std::{
    io::{Cursor, Read},
    net::{Ipv4Addr, SocketAddrV4},
};

use super::addresses::IndividualAddress;

/// 03.08.02 Core section - 2.3.2 Header length
pub const KNX_NET_IP_HEADER_LENGTH: u8 = 6;
/// 03.08.02 Core section - 2.3.3 Protocol version = 1.0
pub const KNX_NET_IP_PROTOCOL_VERSION: u8 = 0x10;

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

/// 03.08.02 Core section 8.5.2.1 KNXnet/IP system setup multicast address
pub const SYSTEM_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
/// 03.08.02 Core section 8.6.3.2 Discovery Endpoint
pub const DISCOVERY_ENDPOINT_PORT: u16 = 3671;

/// 03.08.02 Core section 8.5.2 Header
///
/// Version 1.0
pub struct KnxNetIpHeader {
    pub service_type_identifier: u16,
    pub total_length: u16,
}

impl KnxNetIpHeader {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![KNX_NET_IP_HEADER_LENGTH, KNX_NET_IP_PROTOCOL_VERSION];
        packet.write_u16::<BigEndian>(self.service_type_identifier).unwrap();
        packet.write_u16::<BigEndian>(self.total_length).unwrap();
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let _header_length = match packet_reader.read_u8() {
            Ok(header_length) => {
                ensure_whatever!(
                    header_length == KNX_NET_IP_HEADER_LENGTH,
                    "Header length should be {} instead of {}",
                    KNX_NET_IP_HEADER_LENGTH,
                    header_length
                );
                header_length
            }
            Err(e) => whatever!("Unable to read header length {:?}", e),
        };

        match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(
                    version == KNX_NET_IP_PROTOCOL_VERSION,
                    "KNXIP protocol version should be 0x10 instead of {:2X}",
                    KNX_NET_IP_PROTOCOL_VERSION
                );
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let service_type_identifier = packet_reader
            .read_u16::<BigEndian>()
            .whatever_context("Unable to read service type identifier")?;

        let total_length = packet_reader.read_u16::<BigEndian>().whatever_context("Unable to read total length")?;

        Ok(Self {
            service_type_identifier,
            total_length,
        })
    }
}

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
        let _size = match packet_reader.read_u8() {
            Ok(size) => {
                ensure_whatever!(size == 4, "Connection Response Data Block should have length 4 instead of {}", size);
                size
            }
            Err(e) => whatever!("Unable to read CRD packet size {:?}", e),
        };
        let _tunnel_connection = match packet_reader.read_u8() {
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
    pub fn get_status(&self) -> u8 {
        self.status
    }
    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        let _version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let _connect_response = match packet_reader.read_u16::<BigEndian>() {
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

        let _size = match packet_reader.read_u16::<BigEndian>() {
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

        let data_endpoint = HPAI::from_packet(packet_reader)?;
        let crd = CRD::from_packet(packet_reader)?;

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

        let _size = match packet_reader.read_u16::<BigEndian>() {
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
    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size == 6, "Header size should be 6 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        let _version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let _connectionstate_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x0208, "Connect response should be 0x0208 instead of {:2X}", code);
                code
            }
            Err(e) => whatever!("Unable to read Connectstate Response {:?}", e),
        };

        let _size = match packet_reader.read_u16::<BigEndian>() {
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

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header_size = match packet_reader.read_u8() {
            Ok(header_size) => {
                ensure_whatever!(header_size >= 8, "Header size should be at least 8 instead of {}", header_size);
                header_size
            }
            Err(e) => whatever!("Unable to read header size {:?}", e),
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(communication_channel_id) => communication_channel_id,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        let _reserved = match packet_reader.read_u8() {
            Ok(reserved) => reserved,
            Err(e) => whatever!("Unable to read reserved data {:?}", e),
        };

        let control_endpoint = HPAI::from_packet(packet_reader)?;

        Ok(Self {
            communication_channel_id,
            control_endpoint,
        })
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
    pub fn from_disconnect_request(req: &DisconnectRequest) -> Self {
        Self {
            communication_channel_id: req.communication_channel_id,
            status: 0, // No error
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

        let _version = match packet_reader.read_u8() {
            Ok(version) => {
                ensure_whatever!(version == 0x10, "KNXIP version should be 0x10 instead of {:2X}", header_size);
                version
            }
            Err(e) => whatever!("Unable to read KNXIP version {:?}", e),
        };

        let _connectionstate_response = match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x020a, "Disconnect response should be 0x020A instead of {:2X}", code);
                code
            }
            Err(e) => whatever!("Unable to read Disconnect Response {:?}", e),
        };

        let _size = match packet_reader.read_u16::<BigEndian>() {
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
        let mut packet = vec![0x06, 0x10, 0x02, 0x0A];
        packet.write_u16::<BigEndian>(8).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(self.status).unwrap();

        packet
    }
}

/// Search request
/// 03.08.02 Core section 7.6.1
///
#[derive(Debug)]
pub struct SearchRequest {
    discovery_endpoint: HPAI,
}

impl SearchRequest {
    /// UDP search request, expecting responses on the default discovery multicast address.
    /// This ensures, reception from KNXNet/IP Servers on different subnets.
    /// 03.08.02 Core section 4.2 Discovery
    pub fn udp() -> Self {
        let mut discovery_endpoint = HPAI::udp();
        discovery_endpoint.set_addr(SocketAddrV4::new(SYSTEM_MULTICAST_ADDRESS, DISCOVERY_ENDPOINT_PORT));
        Self { discovery_endpoint }
    }

    /// UDP search request providing a unicast IP address to receive the response via point-to-point communication (unicast).
    /// 03.08.02 Core section 4.2 Discovery
    pub fn udp_unicast(unicast_endpoint: SocketAddrV4) -> Self {
        let mut discovery_endpoint = HPAI::udp();
        discovery_endpoint.set_addr(unicast_endpoint);
        Self { discovery_endpoint }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x02, 0x01];
        let mut hpai_packet = self.discovery_endpoint.packet();
        let size = packet.len() + 2 + hpai_packet.len();
        packet.write_u16::<BigEndian>(size as u16).unwrap();
        packet.append(&mut hpai_packet);

        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header = KnxNetIpHeader::from_packet(packet_reader)?;
        ensure_whatever!(
            header.service_type_identifier == 0x0201,
            "Search request should be 0x0201 instead of {:2X}",
            header.service_type_identifier
        );

        let discovery_endpoint = HPAI::from_packet(packet_reader)?;

        Ok(SearchRequest { discovery_endpoint })
    }
}

/// Search response
/// 03.08.02 Core section 7.6.2
///
#[derive(Debug, Clone)]
pub struct SearchResponse {
    pub control_endpoint: HPAI,
    pub device_hardware: DeviceInformationDIB,
    pub supported_service_families: SupportedServiceFamiliesDIB,
}

impl SearchResponse {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x02, 0x02];

        let mut control_endpoint_packet = self.control_endpoint.packet();
        let mut device_hardware_packet = self.device_hardware.packet();
        let mut supported_service_families_packet = self.supported_service_families.packet();
        let size = packet.len() + 2 + control_endpoint_packet.len() + device_hardware_packet.len() + supported_service_families_packet.len();

        packet.write_u16::<BigEndian>(size as u16).unwrap();
        packet.append(&mut control_endpoint_packet);
        packet.append(&mut device_hardware_packet);
        packet.append(&mut supported_service_families_packet);

        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let header = KnxNetIpHeader::from_packet(packet_reader)?;
        ensure_whatever!(
            header.service_type_identifier == 0x0202,
            "Search response should be 0x0202 instead of {:2X}",
            header.service_type_identifier
        );

        let control_endpoint = HPAI::from_packet(packet_reader)?;

        let device_hardware: DeviceInformationDIB = match DIB::from_packet(packet_reader)? {
            DIB::DeviceInformation(device_hardware) => device_hardware,
            other => whatever!("Expected device information dib instead of {:?}", other),
        };

        let supported_service_families = match DIB::from_packet(packet_reader)? {
            DIB::SupportedServiceFamilies(supported_service_families) => supported_service_families,
            other => whatever!("Expected supported service families dib instead of {:?}", other),
        };

        Ok(Self {
            control_endpoint,
            device_hardware,
            supported_service_families,
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
    pub host_protocol_code: u8,
    pub address: SocketAddrV4,
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

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let _size = match packet_reader.read_u8() {
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

/// 03.08.02 Core section 7.5.4.1
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum DescriptionTypeCode {
    DeviceInfo = 0x01,
    SupportedServiceFamilies = 0x02,
    IpConfig = 0x03,
    IpCurrentConfig = 0x04,
    KNXAddresses = 0x05,
    ManufacturerData = 0xFE,
}

impl TryFrom<u8> for DescriptionTypeCode {
    type Error = Whatever;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::DeviceInfo),
            0x02 => Ok(Self::SupportedServiceFamilies),
            0x03 => Ok(Self::IpConfig),
            0x04 => Ok(Self::IpCurrentConfig),
            0x05 => Ok(Self::KNXAddresses),
            0xFE => Ok(Self::ManufacturerData),
            _ => whatever!("Unknown DescriptionTypeCode {}", value),
        }
    }
}

/// Description Information Block (DIB)
/// 03.08.02 Core section 7.5.4.1
#[derive(Debug, Clone)]
pub enum DIB {
    DeviceInformation(DeviceInformationDIB),
    SupportedServiceFamilies(SupportedServiceFamiliesDIB),
    IpConfig(IpConfigDIB),
    IpCurrentConfig(IpCurrentConfigDIB),
    KNXAddresses(KNXAddressesDIB),
    ManufacturerData(ManufacturerDataDIB),
}

impl DIB {
    pub fn structure_length(&self) -> u8 {
        match self {
            Self::DeviceInformation(device_information) => device_information.structure_length,
            Self::SupportedServiceFamilies(supported_service_families) => supported_service_families.structure_length,
            Self::IpConfig(ip_config) => ip_config.structure_length,
            Self::IpCurrentConfig(ip_current_config) => ip_current_config.structure_length,
            Self::KNXAddresses(knx_addresses) => knx_addresses.structure_length,
            Self::ManufacturerData(manufacturer_data) => manufacturer_data.structure_length,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        let (type_code, data_packet) = match self {
            Self::DeviceInformation(device_information) => (DescriptionTypeCode::DeviceInfo, device_information.packet()),
            Self::SupportedServiceFamilies(families) => (DescriptionTypeCode::SupportedServiceFamilies, families.packet()),
            Self::IpConfig(ip_config) => (DescriptionTypeCode::IpConfig, ip_config.packet()),
            Self::IpCurrentConfig(ip_current_config) => (DescriptionTypeCode::IpCurrentConfig, ip_current_config.packet()),
            Self::KNXAddresses(knx_addresses) => (DescriptionTypeCode::KNXAddresses, knx_addresses.packet()),
            Self::ManufacturerData(manufacturer_data) => (DescriptionTypeCode::ManufacturerData, manufacturer_data.packet()),
        };

        let structure_length = 2 + data_packet.len();
        packet.write_u8(structure_length as u8).unwrap();
        packet.write_u8(type_code as u8).unwrap();
        packet.extend_from_slice(&data_packet);

        // 7.5.4.1
        // Structure length must be even. Add a padding of 0x00 if necessary.
        if structure_length % 2 != 0 {
            packet.write_u8(0x00).unwrap();
        }

        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        let structure_length = packet_reader.read_u8().whatever_context("Unable to read structure length")?;
        let description_type_code = packet_reader.read_u8().whatever_context("Unable to read structure length")?;
        let description_type_code = DescriptionTypeCode::try_from(description_type_code)?;

        let dib = match description_type_code {
            DescriptionTypeCode::DeviceInfo => {
                let device_info = DeviceInformationDIB::from_packet(packet_reader, structure_length)?;
                DIB::DeviceInformation(device_info)
            }
            DescriptionTypeCode::SupportedServiceFamilies => {
                let service_families = SupportedServiceFamiliesDIB::from_packet(packet_reader, structure_length)?;
                DIB::SupportedServiceFamilies(service_families)
            }
            DescriptionTypeCode::IpConfig => {
                let ip_config = IpConfigDIB::from_packet(packet_reader, structure_length)?;
                DIB::IpConfig(ip_config)
            }
            DescriptionTypeCode::IpCurrentConfig => {
                let ip_current_config = IpCurrentConfigDIB::from_packet(packet_reader, structure_length)?;
                DIB::IpCurrentConfig(ip_current_config)
            }
            DescriptionTypeCode::KNXAddresses => {
                let knx_addresses = KNXAddressesDIB::from_packet(packet_reader, structure_length)?;
                DIB::KNXAddresses(knx_addresses)
            }
            DescriptionTypeCode::ManufacturerData => {
                let manufacture_data = ManufacturerDataDIB::from_packet(packet_reader, structure_length)?;
                DIB::ManufacturerData(manufacture_data)
            }
        };

        Ok(dib)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum KnxMedium {
    TP1 = 0x02,
    PL110 = 0x03,
    RF = 0x10,
    IP = 0x20,
}

impl TryFrom<u8> for KnxMedium {
    type Error = Whatever;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x02 => Ok(Self::TP1),
            0x03 => Ok(Self::PL110),
            0x10 => Ok(Self::RF),
            0x20 => Ok(Self::IP),
            _ => whatever!("Unknown KnxMedium {}", value),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, PartialEq)]
    pub struct DeviceStatus: u8 {
        /// Is device in programming mode?
        const PROGRAMMING_MODE = 0b0000_0001;
        // remaining bits are reserved but undefined so far
    }
}

/// Device information DIB
/// 03.08.02 Core section 7.5.4.2
#[derive(Debug, Clone)]
pub struct DeviceInformationDIB {
    pub structure_length: u8,
    pub description_type_code: DescriptionTypeCode,
    pub knx_medium: KnxMedium,
    pub knx_device_status: DeviceStatus,
    pub knx_individual_address: IndividualAddress,
    pub project_installation_identifier: u16,
    pub serial_number: [u8; 6],
    pub routing_multicast_address: Ipv4Addr,
    pub mac_address: [u8; 6],
    /// ISO 8859-1 string
    pub friendly_name: [u8; 30],
}

impl DeviceInformationDIB {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        structure_length: u8,
        knx_medium: KnxMedium,
        knx_device_status: DeviceStatus,
        knx_individual_address: IndividualAddress,
        project_installation_identifier: u16,
        serial_number: [u8; 6],
        routing_multicast_address: Ipv4Addr,
        mac_address: [u8; 6],
        friendly_name: String,
    ) -> Result<Self, Whatever> {
        let friendly_name = ISO_8859_1
            .encode(&friendly_name, EncoderTrap::Strict)
            .whatever_context("Unable to encode device friendly name")?;
        let friendly_name = friendly_name
            .try_into()
            .map_err(|_err| "")
            .whatever_context("Encoded friendly name length exceeds 30 bytes")?;

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::DeviceInfo,
            knx_medium,
            knx_device_status,
            knx_individual_address,
            project_installation_identifier,
            serial_number,
            routing_multicast_address,
            mac_address,
            friendly_name,
        })
    }

    /// Device friendly name decoded from ISO 8859-1
    pub fn friendly_name(&self) -> Result<String, Whatever> {
        ISO_8859_1
            .decode(&self.friendly_name, DecoderTrap::Strict)
            .whatever_context("Unable to decode friendly name")
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.write_u8(self.knx_medium as u8).unwrap();
        packet.write_u8(self.knx_device_status.bits()).unwrap();
        packet.write_u16::<BigEndian>(self.knx_individual_address.to_u16()).unwrap();
        packet.write_u16::<BigEndian>(self.project_installation_identifier).unwrap();
        packet.extend_from_slice(&self.serial_number);
        packet.extend_from_slice(&self.routing_multicast_address.octets());
        packet.extend_from_slice(&self.mac_address);
        packet.extend_from_slice(&self.friendly_name);
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>, structure_length: u8) -> Result<Self, Whatever> {
        let knx_medium = packet_reader.read_u8().whatever_context("Unable to read knx mediumn")?;
        let knx_medium = KnxMedium::try_from(knx_medium)?;
        let knx_device_status = packet_reader.read_u8().whatever_context("Unable to read knx device status")?;
        let knx_device_status = DeviceStatus::from_bits_truncate(knx_device_status);

        let knx_individual_address = packet_reader
            .read_u16::<BigEndian>()
            .whatever_context("Unable to read knx individual address")?;
        let knx_individual_address = IndividualAddress::from_u16(knx_individual_address);

        let project_installation_identifier = packet_reader
            .read_u16::<BigEndian>()
            .whatever_context("Unable to read project installation identifier")?;

        let mut serial_number = [0; 6];
        packet_reader.read_exact(&mut serial_number).whatever_context("Unable to read serial number")?;

        let mut routing_multicast_address = [0; 4];
        packet_reader
            .read_exact(&mut routing_multicast_address)
            .whatever_context("Unable to read routing multicast address")?;

        let mut mac_address = [0; 6];
        packet_reader.read_exact(&mut mac_address).whatever_context("Unable to read mac address")?;

        let mut friendly_name = [0; 30];
        packet_reader.read_exact(&mut friendly_name).whatever_context("Unable to read friendly name")?;

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::DeviceInfo,
            knx_medium,
            knx_device_status,
            knx_individual_address,
            project_installation_identifier,
            serial_number,
            routing_multicast_address: Ipv4Addr::from(routing_multicast_address),
            mac_address,
            friendly_name,
        })
    }
}

/// Supported service families DIB
/// 03.08.02 Core section 7.5.4.3
#[derive(Debug, Clone)]
pub struct ServiceFamily {
    pub service_family: u8,
    pub version: u8,
}

/// Supported service families DIB
/// 03.08.02 Core section 7.5.4.3
#[derive(Debug, Clone)]
pub struct SupportedServiceFamiliesDIB {
    pub structure_length: u8,
    pub description_type_code: DescriptionTypeCode,
    pub service_families: Vec<ServiceFamily>,
}

impl SupportedServiceFamiliesDIB {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        for service_family in &self.service_families {
            packet.write_u8(service_family.service_family).unwrap();
            packet.write_u8(service_family.version).unwrap();
        }

        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>, structure_length: u8) -> Result<Self, Whatever> {
        let mut service_families = Vec::new();
        for _ in 0..(structure_length - 2) / 2 {
            // -2 because of length and type
            let service_family = packet_reader.read_u8().whatever_context("Unable to read service family")?;
            let version: u8 = packet_reader.read_u8().whatever_context("Unable to read version")?;
            service_families.push(ServiceFamily { service_family, version });
        }

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::SupportedServiceFamilies,
            service_families,
        })
    }
}

/// IP Config DIB
/// 03.08.02 Core section 7.5.4.4
#[derive(Debug, Clone)]
pub struct IpConfigDIB {
    pub structure_length: u8,
    pub description_type_code: DescriptionTypeCode,
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub default_gateway: Ipv4Addr,
    pub ip_capabilities: u8,
    pub ip_assignment_method: u8,
}

impl IpConfigDIB {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.ip_address.octets());
        packet.extend_from_slice(&self.subnet_mask.octets());
        packet.extend_from_slice(&self.default_gateway.octets());
        packet.write_u8(self.ip_capabilities).unwrap();
        packet.write_u8(self.ip_assignment_method).unwrap();
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>, structure_length: u8) -> Result<Self, Whatever> {
        let mut ip_address = [0; 4];
        packet_reader.read_exact(&mut ip_address).whatever_context("Unable to read ip address")?;
        let ip_address = Ipv4Addr::from(ip_address);

        let mut subnet_mask = [0; 4];
        packet_reader.read_exact(&mut subnet_mask).whatever_context("Unable to read subnet_mask")?;
        let subnet_mask = Ipv4Addr::from(subnet_mask);

        let mut default_gateway = [0; 4];
        packet_reader
            .read_exact(&mut default_gateway)
            .whatever_context("Unable to read default gateway")?;
        let default_gateway = Ipv4Addr::from(default_gateway);

        let ip_capabilities = packet_reader.read_u8().whatever_context("Unable to read ip capabilities")?;
        let ip_assignment_method = packet_reader.read_u8().whatever_context("Unable to read ip assignment method")?;

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::IpConfig,
            ip_address,
            subnet_mask,
            default_gateway,
            ip_capabilities,
            ip_assignment_method,
        })
    }
}

/// IP Current Config DIB
/// 03.08.02 Core section 7.5.4.5
#[derive(Debug, Clone)]
pub struct IpCurrentConfigDIB {
    pub structure_length: u8,
    pub description_type_code: DescriptionTypeCode,
    pub current_ip_address: Ipv4Addr,
    pub current_subnet_mask: Ipv4Addr,
    pub current_default_gateway: Ipv4Addr,
    pub dhcp_server: Ipv4Addr,
    pub current_ip_assignment_method: u8,
    pub reserved: u8,
}

impl IpCurrentConfigDIB {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.current_ip_address.octets());
        packet.extend_from_slice(&self.current_subnet_mask.octets());
        packet.extend_from_slice(&self.current_default_gateway.octets());
        packet.extend_from_slice(&self.dhcp_server.octets());
        packet.write_u8(self.current_ip_assignment_method).unwrap();
        packet.write_u8(self.reserved).unwrap();
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>, structure_length: u8) -> Result<Self, Whatever> {
        let mut current_ip_address = [0; 4];
        packet_reader
            .read_exact(&mut current_ip_address)
            .whatever_context("Unable to read current ip address")?;
        let current_ip_address = Ipv4Addr::from(current_ip_address);

        let mut current_subnet_mask = [0; 4];
        packet_reader
            .read_exact(&mut current_subnet_mask)
            .whatever_context("Unable to read current subnet_mask")?;
        let current_subnet_mask = Ipv4Addr::from(current_subnet_mask);

        let mut current_default_gateway = [0; 4];
        packet_reader
            .read_exact(&mut current_default_gateway)
            .whatever_context("Unable to read current default gateway")?;
        let current_default_gateway = Ipv4Addr::from(current_default_gateway);

        let mut dhcp_server = [0; 4];
        packet_reader.read_exact(&mut dhcp_server).whatever_context("Unable to read dhcp server")?;
        let dhcp_server = Ipv4Addr::from(dhcp_server);

        let current_ip_assignment_method = packet_reader.read_u8().whatever_context("Unable to read current ip assignment method")?;
        let reserved = packet_reader.read_u8().whatever_context("Unable to read reserved")?;

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::IpCurrentConfig,
            current_ip_address,
            current_subnet_mask,
            current_default_gateway,
            dhcp_server,
            current_ip_assignment_method,
            reserved,
        })
    }
}

/// KNX Addresses DIB
/// 03.08.02 Core section 7.5.4.6
#[derive(Debug, Clone)]
pub struct KNXAddressesDIB {
    pub structure_length: u8,
    pub description_type_code: DescriptionTypeCode,
    pub knx_individual_address: Ipv4Addr,
    pub additional_individual_addresses: Vec<Ipv4Addr>,
}

impl KNXAddressesDIB {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.knx_individual_address.octets());
        for address in &self.additional_individual_addresses {
            packet.extend_from_slice(&address.octets());
        }
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>, structure_length: u8) -> Result<Self, Whatever> {
        let mut knx_individual_address = [0; 4];
        packet_reader
            .read_exact(&mut knx_individual_address)
            .whatever_context("Unable to read knx individual address")?;

        let mut additional_individual_addresses = Vec::new();

        for _ in 0..(structure_length - 4) / 2 {
            // - 1 byte structure length - 2 byte description type code  - 2 bytes knx individual address
            let mut additional_individual_address = [0; 4];
            packet_reader
                .read_exact(&mut additional_individual_address)
                .whatever_context("Unable to read additional individual address")?;
            additional_individual_addresses.push(Ipv4Addr::from(additional_individual_address));
        }

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::KNXAddresses,
            knx_individual_address: Ipv4Addr::from(knx_individual_address),
            additional_individual_addresses,
        })
    }
}

/// Manufacturer data DIB
/// 03.08.02 Core section 7.5.4.7
#[derive(Debug, Clone)]
pub struct ManufacturerDataDIB {
    pub structure_length: u8,
    pub description_type_code: DescriptionTypeCode,
    pub knx_manufacturer_id: u16,
    pub manufacturer_specific_data: Vec<u8>,
}

impl ManufacturerDataDIB {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.write_u16::<BigEndian>(self.knx_manufacturer_id).unwrap();
        packet.extend_from_slice(&self.manufacturer_specific_data);
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>, structure_length: u8) -> Result<Self, Whatever> {
        let knx_manufacturer_id = packet_reader.read_u16::<BigEndian>().whatever_context("Unable to read knx manufacturer id")?;

        let mut manufacturer_specific_data = vec![0; structure_length as usize];
        packet_reader
            .read_exact(&mut manufacturer_specific_data)
            .whatever_context("Unable to read manufacturer specific data")?;

        Ok(Self {
            structure_length,
            description_type_code: DescriptionTypeCode::ManufacturerData,
            knx_manufacturer_id,
            manufacturer_specific_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encoding::all::ISO_8859_1;
    use encoding::{EncoderTrap, Encoding};

    #[test]
    fn parse_search_request() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x06, 0x10]); // header size + version
        packet.extend_from_slice(&[0x02, 0x01]); // service type identifier
        packet.extend_from_slice(&[0x00, 0x0E]); // total length
        packet.extend_from_slice(&[0x08]); // structure length
        packet.extend_from_slice(&[0x01]); // host protocol code - UDP over ipv4
        packet.extend_from_slice(&[192, 168, 200, 12]); // ip address of control endpoint
        packet.extend_from_slice(&[0x0E, 0x57]); // port control endpoint 3671
        let mut c = Cursor::new(packet.as_slice());

        let request = SearchRequest::from_packet(&mut c).unwrap();
        assert_eq!(request.discovery_endpoint.address, SocketAddrV4::new(Ipv4Addr::new(192, 168, 200, 12), 3671));
    }

    #[test]
    /// 8.8.2 Binary examples of KNXnet/IP IP frames - SEARCH_RESPONSE
    fn parse_search_response() {
        let mut packet = Vec::new();

        // header
        packet.extend_from_slice(&[0x06, 0x10, 0x02, 0x02, 0x00, 0x4E]);

        // hpai
        packet.extend_from_slice(&[0x08, 0x01]);

        // ip address of control endpoint
        packet.extend_from_slice(&[192, 168, 200, 12]);

        packet.extend_from_slice(&[0xC3, 0xB4, 0x36, 0x01, 0x02, 0x01, 0x11, 0x00, 0x00, 0x11]);

        // knx device serial number
        packet.extend_from_slice(&[0x00, 0x01, 0x11, 0x11, 0x11, 0x11]);

        // device routing multicast address
        packet.extend_from_slice(&[224, 0, 23, 12]);

        // Mac Address
        packet.extend_from_slice(&[0x45, 0x49, 0x42, 0x6E, 0x65, 0x74]);

        // Device Friendly Name
        packet.extend_from_slice(&[b'M', b'Y', b'H', b'O', b'M', b'E', b'\n']);
        // Device Friendly Name Padding (total 30 bytes)
        packet.append(&mut vec![0x00; 23]);

        packet.extend_from_slice(&[0x0A, 0x02, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01]);

        let mut c = Cursor::new(packet.as_slice());

        let result = SearchResponse::from_packet(&mut c).unwrap();

        assert_eq!(result.device_hardware.knx_medium, KnxMedium::TP1);
        assert_eq!(result.device_hardware.knx_device_status, DeviceStatus::PROGRAMMING_MODE);
        assert_eq!(result.device_hardware.knx_individual_address, IndividualAddress::try_from("1.1.0").unwrap());
        assert_eq!(result.device_hardware.project_installation_identifier, 0x0011);
        assert_eq!(result.device_hardware.serial_number, [0x00, 0x01, 0x11, 0x11, 0x11, 0x11]);
        assert_eq!(result.device_hardware.routing_multicast_address, Ipv4Addr::from([224, 0, 23, 12]));
        assert_eq!(result.device_hardware.mac_address, [0x45, 0x49, 0x42, 0x6E, 0x65, 0x74]);
        let mut friendly_name = ISO_8859_1.encode("MYHOME\n", EncoderTrap::Strict).unwrap();
        friendly_name.resize(30, 0x00); // pad it
        assert_eq!(result.device_hardware.friendly_name.to_vec(), friendly_name);

        // service families

        assert_eq!(result.supported_service_families.service_families.len(), 4);
        assert_eq!(result.supported_service_families.service_families[0].service_family, 2);
        assert_eq!(result.supported_service_families.service_families[0].version, 1);
    }
}
