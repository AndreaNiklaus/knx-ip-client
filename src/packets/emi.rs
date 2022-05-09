use super::addresses::KnxAddress;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use snafu::{Whatever, whatever};
use std::io::{Cursor, Read};

#[derive(Debug)]
pub struct LDataCon {
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

#[derive(Debug)]
pub struct LData {
    src: u16,
    dest: u16,
    frame_type: bool,
    repetition: bool,
    system_broadcast: bool,
    ack_request: bool,
}

#[derive(Debug)]
pub struct LDataInd {
    pub cemi: CEMI,
    pub l_data: LData,
    pub value: Vec<u8>,
}

impl LDataInd {
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
        let length = match reader.read_u8() {
            Ok(len) => len - 1,
            Err(e) => whatever!("Unable to read length {:?}", e),
        };
        let octects_6_7 = match reader.read_u16::<BigEndian>() {
            Ok(word) => word,
            Err(e) => whatever!("Unable to read octets 6 and 7 {:?}", e),
        };

        let frame_type = (control1 & 0x80) > 0;
        let repetition = (control1 & (1 << 5)) > 0;
        let system_broadcast = (control1 & (1 << 4)) > 0;
        let ack_request = (control1 & (1 << 1)) > 0;

        let acpi = (octects_6_7 & 0x03c0) >> 6;
        println!("Length {:?}", length);
        println!("Octects 6 and 7: {:0x?}", octects_6_7);
        println!("Apci: {:0x?}", acpi);

        let mut value = vec![0; length as usize];
        if let Err(e) = reader.read(&mut value) {
            whatever!("Unable to read value of length {}, {:?}", length, e);
        }
        println!("Value: {:0x?}", value);

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
            value,
        })
    }
}

// L_Data request message
// 03.06.03 EMI IMI section 4.1.5.3.3
#[derive(Debug)]
pub struct LDataReqMessage {
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

// cEMI
//
#[derive(Debug)]
pub struct CEMI {
    pub msg_code: u8,
    pub additional_infos: Vec<CEMIAdditionalInfo>,
    pub service_info: Vec<u8>,
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
pub enum CEMIMessageCode {
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
pub enum CEMIAdditionalInfoType {
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
pub struct CEMIAdditionalInfo {
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

