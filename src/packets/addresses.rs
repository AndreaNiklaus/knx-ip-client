use std::fmt;

use snafu::{whatever, Whatever};


// KNX Address
//
#[derive(Debug)]
pub enum KnxAddress {
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

    pub fn group_1_level(main: u16) -> Self {
        Self::Group1Level(Group1LevelAddress {
            main,
        })
    }

    pub fn group_2_level(main: u8, sub: u8) -> Self {
        Self::Group2Level(Group2LevelAddress {
            main,
            sub,
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

impl TryFrom<&str> for KnxAddress {
    type Error = Whatever;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let is_individual = value.contains(".");

        if is_individual {
            let addr = IndividualAddress::try_from(value)?;
            Ok(Self::Individual(addr))
        } else {
            let parts: Vec<&str> = value.split('/').collect();
            if parts.len() == 1 {
                let main = parts.get(0).unwrap();
                let main = match main.parse::<u16>() {
                    Ok(main) => main,
                    Err(e) => whatever!("Unable to parse main address {} {:?}", main, e)
                };

                Ok(Self::group_1_level(main))
            } else if parts.len() == 2 {
                let main = parts.get(0).unwrap();
                let main = match main.parse::<u8>() {
                    Ok(main) => main,
                    Err(e) => whatever!("Unable to parse main address {:?}", e)
                };
                let sub = parts.get(1).unwrap();
                let sub = match sub.parse::<u8>() {
                    Ok(sub) => sub,
                    Err(e) => whatever!("Unable to parse sub address {:?}", e)
                };

                Ok(Self::group_2_level(main, sub))
            } else if parts.len() == 3 {
                let main = parts.get(0).unwrap();
                let main = match main.parse::<u8>() {
                    Ok(main) => main,
                    Err(e) => whatever!("Unable to parse main address {:?}", e)
                };
                let mid = parts.get(1).unwrap();
                let mid = match mid.parse::<u8>() {
                    Ok(mid) => mid,
                    Err(e) => whatever!("Unable to parse mid address {:?}", e)
                };
                let sub = parts.get(2).unwrap();
                let sub = match sub.parse::<u8>() {
                    Ok(sub) => sub,
                    Err(e) => whatever!("Unable to parse sub address {:?}", e)
                };

                Ok(Self::group_3_level(main, mid, sub))
            } else {
                whatever!("Unable to parse group address {:?}, parts should be 1 to 3", value)
            }
        }
    }
}

pub struct IndividualAddress {
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

impl TryFrom<&str> for IndividualAddress {
    type Error = Whatever;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 3 {
            whatever!("Individial address should be in the format area.line.address instead of {:?}", value);
        }
        let area = match parts.get(0).unwrap().parse::<u8>() {
            Ok(a) => a,
            Err(e) => whatever!("Unable to parse area value {:?}, error {:?}", parts.get(0), e),
        };
        let line = match parts.get(1).unwrap().parse::<u8>() {
            Ok(l) => l,
            Err(e) => whatever!("Unable to parse line value {:?}, error {:?}", parts.get(1), e),
        };
        let address = match parts.get(2).unwrap().parse::<u8>() {
            Ok(a) => a,
            Err(e) => whatever!("Unable to parse address value {:?}, error {:?}", parts.get(2), e),
        };
        Ok(Self{
            area, line, address
        })
    }
}

impl fmt::Debug for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.area, self.line, self.address)
    }
}

pub struct Group3LevelAddress {
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

pub struct Group2LevelAddress {
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

pub struct Group1LevelAddress {
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
    fn parse_individual_address() {
        let addr: KnxAddress = "1.2.3".try_into().expect("Should be able to parse individual address");
        match addr {
            KnxAddress::Individual(addr) => {
                assert_eq!(addr.area, 1, "Area should be 1");
                assert_eq!(addr.line, 2, "Line should be 2");
                assert_eq!(addr.address, 3, "Address should be 3");
            },
            _ => panic!("Wrong KnxAddress type")
        }

        let addr: Result<KnxAddress, _> = "1.2.3.4".try_into();
        assert!(addr.is_err(), "Should not be able to parse '1.2.3.4' address");

        let addr: Result<KnxAddress, _> = "1.2".try_into();
        assert!(addr.is_err(), "Should not be able to parse '1.2' address");

        let addr: Result<KnxAddress, _> = "1.2.256".try_into();
        assert!(addr.is_err(), "Should not be able to parse '1.2.256' address, 256 is out of range");
    }

    #[test]
    fn parse_group_address() {
        let addr: KnxAddress = "1".try_into().expect("Should be able to parse individual address");
        match addr {
            KnxAddress::Group1Level(addr) => {
                assert_eq!(addr.main, 1, "Main should be 1");
            },
            _ => panic!("Wrong KnxAddress type")
        }

        let addr: KnxAddress = "1/2".try_into().expect("Should be able to parse individual address");
        match addr {
            KnxAddress::Group2Level(addr) => {
                assert_eq!(addr.main, 1, "Main should be 1");
                assert_eq!(addr.sub, 2, "Sub should be 2");
            },
            _ => panic!("Wrong KnxAddress type")
        }

        let addr: KnxAddress = "1/2/3".try_into().expect("Should be able to parse individual address");
        match addr {
            KnxAddress::Group3Level(addr) => {
                assert_eq!(addr.main, 1, "Main should be 1");
                assert_eq!(addr.middle, 2, "Middle should be 2");
                assert_eq!(addr.sub, 3, "Sub should be 3");
            },
            _ => panic!("Wrong KnxAddress type")
        }

        let addr: Result<KnxAddress, _> = "1/2/3/4".try_into();
        assert!(addr.is_err(), "Should not be able to parse '1/2/3/4' address");
    }
}
