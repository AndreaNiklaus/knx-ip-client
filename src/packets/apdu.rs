// Application Protocol Data Unit (APDU)
// 03.03.07 Application Layer chapter 2
//
#[derive(Debug)]
pub struct APDU {
    apci: APCI,
    data: APDUData,
}

#[derive(Debug)]
pub enum APDUData {
    Small(u8),
    Big(Vec<u8>),
}

impl APDU {
    pub fn new(apci: APCI, data: APDUData) -> Self {
        Self { apci, data }
    }

    pub fn group_value_read() -> Self {
        Self {
            apci: APCI::a_group_value_read(),
            data: APDUData::Small(0),
        }
    }

    pub fn group_value_write(data: Vec<u8>) -> Self {
        let data = if data.len() == 1 { APDUData::Small(data[0]) } else { APDUData::Big(data) };
        Self {
            apci: APCI::a_group_value_write(),
            data,
        }
    }

    pub fn packet(&self) -> Vec<u8> {
        let mut apci_packet = self.apci.packet();
        match &self.data {
            APDUData::Small(data) => apci_packet[1] |= data & 0x3f,
            APDUData::Big(data) => apci_packet.extend_from_slice(data),
        }

        apci_packet
    }
}

// Application Layer Protocol Control Information (APCI)
// 03.03.07 Application Layer chapter 2
//
#[derive(Debug)]
pub struct APCI {
    code: u8,
    extended_code: Option<u8>,
}

impl APCI {
    pub fn a_group_value_read() -> Self {
        Self {
            code: 0,
            extended_code: Some(0),
        }
    }

    pub fn a_group_value_write() -> Self {
        Self { code: 2, extended_code: None }
    }

    pub fn packet(&self) -> Vec<u8> {
        let hw = (self.code & 0b1100) >> 2;
        let mut lw = (self.code & 0b11) << 6;

        if let Some(extended_code) = self.extended_code {
            lw |= extended_code & 0x3f;
        }

        vec![hw, lw]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_read() {
        let packet = APCI::a_group_value_read().packet();
        assert_eq!(packet[0], 0x00, "Group value read HW should be 0x00");
        assert_eq!(packet[1], 0x00, "Group value read LW should be 0x00");
    }
}
