use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use snafu::{ensure_whatever, whatever, Whatever};
use std::io::{Cursor, Read};

// Tunneling request
// 03.08.04 Tunneling section 4.4.6
//
#[derive(Debug)]
pub struct TunnelingRequest {
    pub communication_channel_id: u8,
    pub sequence_nr: u8,
    pub cemi: Vec<u8>,
}

impl TunnelingRequest {
    pub fn new(communication_channel_id: u8, sequence_nr: u8, cemi: Vec<u8>) -> Self {
        Self {
            communication_channel_id,
            sequence_nr,
            cemi,
        }
    }

    pub fn get_cemi(&self) -> &Vec<u8> {
        &self.cemi
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
        verify_header(packet_reader)?;

        match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => {
                ensure_whatever!(code == 0x0420, "Code should be 0x0420 instead of {:0x?}", code);
            }
            Err(e) => whatever!("Unable to read code {:?}", e),
        };

        let size = match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => size,
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        };

        match packet_reader.read_u8() {
            Ok(size) => {
                ensure_whatever!(size == 0x04, "Size should be 0x04 instead of {}", size);
            }
            Err(e) => whatever!("Unable to read message code {:?}", e),
        };

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        let sequence_nr = match packet_reader.read_u8() {
            Ok(sequence_nr) => sequence_nr,
            Err(e) => whatever!("Unable to read sequence number {:?}", e),
        };

        match packet_reader.read_u8() {
            Ok(_) => (),
            Err(e) => whatever!("Unable to read padding {:?}", e),
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

// Tunneling Ack
// 03.08.04 Tunneling section 4.4.7
//
#[derive(Debug)]
pub struct TunnelingAck {
    pub communication_channel_id: u8,
    pub sequence_nr: u8,
    pub status: u8,
}

impl TunnelingAck {
    pub fn new(communication_channel_id: u8, sequence_nr: u8, status: u8) -> Self {
        Self {
            communication_channel_id,
            sequence_nr,
            status,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x04, 0x21, 0, 0x0a];
        packet.write_u8(4).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(self.sequence_nr).unwrap();
        packet.write_u8(self.status).unwrap();
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        verify_header(packet_reader)?;

        match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => ensure_whatever!(code == 0x0421, "Response code should be 0x0421 instead of {:0x?}", code),
            Err(e) => whatever!("Unable to read response code {:?}", e),
        }

        match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => ensure_whatever!(size == 0x0a, "Packet size should be 0x0a instead of {:0x?}", size),
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        }

        match packet_reader.read_u8() {
            Ok(struct_size) => ensure_whatever!(struct_size == 0x04, "Structure size should be 0x04 instead of {:0x?}", struct_size),
            Err(e) => whatever!("Unable to read struct size {:?}", e),
        }

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        let sequence_nr = match packet_reader.read_u8() {
            Ok(nr) => nr,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        let status = match packet_reader.read_u8() {
            Ok(status) => status,
            Err(e) => whatever!("Unable to read status {:?}", e),
        };

        Ok(Self {
            communication_channel_id,
            sequence_nr,
            status,
        })
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum KnxIpFeature {
    MaskVersion = 0x02,
    IndividualAddress = 0x06,
    MaxApduLength = 0x07,
    InfoServiceEnable = 0x08,
}

#[derive(Debug)]
pub struct FeatureSet {
    feature: KnxIpFeature,
    value: u8,
    pub communication_channel_id: u8,
    pub sequence_nr: u8,
}

impl FeatureSet {
    pub fn new(communication_channel_id: u8, sequence_nr: u8, feature: KnxIpFeature, value: u8) -> Self {
        Self {
            communication_channel_id,
            sequence_nr,
            feature,
            value,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x04, 0x24, 0, 0x0d];
        packet.write_u8(4).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(self.sequence_nr).unwrap();
        packet.write_u8(0).unwrap();
        packet.write_u8(self.feature as u8).unwrap();
        packet.write_u8(0).unwrap();
        packet.write_u8(self.value).unwrap();
        packet
    }
}

#[derive(Debug)]
pub struct FeatureResp {
    pub feature: KnxIpFeature,
    pub value: u8,
    pub status: u8,
    pub communication_channel_id: u8,
    pub sequence_nr: u8,
}

impl FeatureResp {
    pub fn packet(&self) -> Vec<u8> {
        let mut packet = vec![0x06, 0x10, 0x04, 0x24, 0, 0x0d];
        packet.write_u8(4).unwrap();
        packet.write_u8(self.communication_channel_id).unwrap();
        packet.write_u8(self.sequence_nr).unwrap();
        packet.write_u8(0).unwrap();
        packet.write_u8(self.feature as u8).unwrap();
        packet.write_u8(0).unwrap();
        packet.write_u8(self.value).unwrap();
        packet
    }

    pub fn from_packet(packet_reader: &mut Cursor<&[u8]>) -> Result<Self, Whatever> {
        verify_header(packet_reader)?;

        match packet_reader.read_u16::<BigEndian>() {
            Ok(code) => ensure_whatever!(code == 0x0423, "Response code should be 0x0423 instead of {:0x?}", code),
            Err(e) => whatever!("Unable to read response code {:?}", e),
        }

        match packet_reader.read_u16::<BigEndian>() {
            Ok(size) => ensure_whatever!(size == 0x0d, "Packet size should be 0x0d instead of {:0x?}", size),
            Err(e) => whatever!("Unable to read packet size {:?}", e),
        }

        match packet_reader.read_u8() {
            Ok(struct_size) => ensure_whatever!(struct_size == 0x04, "Structure size should be 0x04 instead of {:0x?}", struct_size),
            Err(e) => whatever!("Unable to read struct size {:?}", e),
        }

        let communication_channel_id = match packet_reader.read_u8() {
            Ok(id) => id,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        let sequence_nr = match packet_reader.read_u8() {
            Ok(nr) => nr,
            Err(e) => whatever!("Unable to read communication channel id {:?}", e),
        };

        match packet_reader.read_u8() {
            Ok(_) => (),
            Err(e) => whatever!("Unable to read reserved field {:?}", e),
        };

        let feature: KnxIpFeature = match packet_reader.read_u8() {
            Ok(feature) => feature.try_into()?,
            Err(e) => whatever!("Unable to read status {:?}", e),
        };

        let status = match packet_reader.read_u8() {
            Ok(status) => status,
            Err(e) => whatever!("Unable to read status {:?}", e),
        };

        let value = match packet_reader.read_u8() {
            Ok(value) => value,
            Err(e) => whatever!("Unable to read value {:?}", e),
        };

        Ok(Self {
            communication_channel_id,
            sequence_nr,
            status,
            feature,
            value,
        })
    }
}

fn verify_header(packet_reader: &mut Cursor<&[u8]>) -> Result<(), Whatever> {
    match packet_reader.read_u8() {
        Ok(size) => ensure_whatever!(size == 6, "Header size should be 6 instead of {}", size),
        Err(e) => whatever!("Unable to read header size"),
    };

    match packet_reader.read_u8() {
        Ok(version) => ensure_whatever!(version == 0x10, "Version should be 0x10 instead of {:0x?}", version),
        Err(e) => whatever!("Unable to read header version"),
    };

    Ok(())
}

impl TryFrom<u8> for KnxIpFeature {
    type Error = Whatever;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == KnxIpFeature::MaskVersion as u8 => Ok(KnxIpFeature::MaskVersion),
            x if x == KnxIpFeature::IndividualAddress as u8 => Ok(KnxIpFeature::IndividualAddress),
            x if x == KnxIpFeature::MaxApduLength as u8 => Ok(KnxIpFeature::MaxApduLength),
            x if x == KnxIpFeature::InfoServiceEnable as u8 => Ok(KnxIpFeature::InfoServiceEnable),
            _ => whatever!("Unknown KNXIP feature {:?}", v),
        }
    }
}
