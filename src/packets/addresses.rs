use std::fmt;


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
