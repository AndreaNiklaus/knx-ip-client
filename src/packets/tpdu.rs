use super::apdu::APDU;

// Transport Protocol Data Unit (TPDU)
// Is the same as the APDU, but with the transport control field
// that depends on transport medium
// 03.03.04 Trasport Layer chapter 2
//
#[derive(Debug)]
pub struct TPDU {
    pub address_type: TpduAddressType,
    pub kind: TpduKind,
    pub numbered: bool,
    pub sequence_number: u8,
    pub apdu: APDU,
}

#[derive(Debug)]
pub enum TpduKind {
    Data,
    Control,
}

#[derive(Debug)]
pub enum TpduAddressType {
    Individual,
    Group,
}

impl TPDU {
    pub fn t_data_broadcast(apdu: APDU) -> Self {
        Self {
            address_type: TpduAddressType::Group,
            kind: TpduKind::Data,
            numbered: false,
            sequence_number: 0,
            apdu,
        }
    }
    pub fn t_data_group(apdu: APDU) -> Self {
        Self {
            address_type: TpduAddressType::Group,
            kind: TpduKind::Data,
            numbered: false,
            sequence_number: 0,
            apdu,
        }
    }
    pub fn t_data_tag_group(apdu: APDU) -> Self {
        Self {
            address_type: TpduAddressType::Group,
            kind: TpduKind::Data,
            numbered: false,
            sequence_number: 1,
            apdu,
        }
    }
    pub fn t_data_individual(apdu: APDU) -> Self {
        Self {
            address_type: TpduAddressType::Individual,
            kind: TpduKind::Data,
            numbered: false,
            sequence_number: 0,
            apdu,
        }
    }
    pub fn t_data_connected(apdu: APDU, sequence_number: u8) -> Self {
        Self {
            address_type: TpduAddressType::Individual,
            kind: TpduKind::Data,
            numbered: true,
            sequence_number,
            apdu,
        }
    }
    pub fn t_connect(apdu: APDU) -> Self {
        Self {
            address_type: TpduAddressType::Individual,
            kind: TpduKind::Control,
            numbered: false,
            sequence_number: 0,
            apdu,
        }
    }
    pub fn t_disconnect(apdu: APDU) -> Self {
        Self {
            address_type: TpduAddressType::Individual,
            kind: TpduKind::Control,
            numbered: false,
            sequence_number: 1,
            apdu,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        self.apdu.packet()
    }
}
