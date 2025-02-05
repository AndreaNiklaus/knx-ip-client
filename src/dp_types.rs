use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt};
use snafu::{whatever, OptionExt, ResultExt, Whatever};

pub trait Pdt<T> {
    fn general(value: T) -> Self;
    fn get_value(&self) -> T;
    fn from_bytes(b: &[u8]) -> Result<Self, Whatever>
    where
        Self: Sized;
    fn get_bytes(&self) -> Vec<u8>;
    fn is_small(&self) -> bool; // Used to determin if we should use small APDU
}

pub struct PdtKnxScaledValue {
    pub code: String,
    pub unit: String,
    value: u8,
}

impl Pdt<u8> for PdtKnxScaledValue {
    fn general(value: u8) -> Self {
        Self {
            code: "5.x".to_string(),
            unit: "".to_string(),
            value,
        }
    }

    fn get_value(&self) -> u8 {
        self.value
    }

    fn from_bytes(b: &[u8]) -> Result<Self, Whatever> {
        let value = b.first().with_whatever_context(|| "At least one byte is needed")?;
        Ok(Self {
            code: "5.001".to_string(),
            unit: "%".to_string(),
            value: *value,
        })
    }

    fn get_bytes(&self) -> Vec<u8> {
        vec![self.value]
    }

    fn is_small(&self) -> bool {
        false
    }
}

impl PdtKnxScaledValue {
    pub fn scaling(percent: f32) -> Self {
        Self {
            code: "5.001".to_string(),
            unit: "%".to_string(),
            value: (percent * 2.54 + 1.0).round() as u8,
        }
    }

    pub fn get_value(&self) -> f32 {
        if self.value == 0 {
            return 0.0;
        }
        (self.value - 1) as f32 / 2.54
    }
}

pub struct PdtKnxInt {
    pub code: String,
    pub unit: String,
    value: i16,
}

impl Pdt<i16> for PdtKnxInt {
    fn general(value: i16) -> Self {
        Self {
            code: "8.x".to_string(),
            unit: "".to_string(),
            value,
        }
    }
    fn get_value(&self) -> i16 {
        self.value
    }

    fn from_bytes(b: &[u8]) -> Result<Self, Whatever>
    where
        Self: Sized,
    {
        let mut reader = Cursor::new(b);
        let value = reader.read_i16::<BigEndian>().with_whatever_context(|e| "Unable to get first byte {e}")?;
        Ok(Self {
            code: "8.x".to_string(),
            unit: "".to_string(),
            value,
        })
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.value.to_be_bytes().into()
    }

    fn is_small(&self) -> bool {
        false
    }
}

impl PdtKnxInt {
    pub fn value_2_count(value: i16) -> Self {
        Self {
            code: "8.001".to_string(),
            unit: "pulses".to_string(),
            value,
        }
    }

    pub fn percent_v16(value: i16) -> Self {
        Self {
            code: "8.010".to_string(),
            unit: "%".to_string(),
            value: value * 100,
        }
    }
}

pub struct PdtKnxFloat {
    pub code: String,
    pub unit: String,
    value: f32,
}

impl Pdt<f32> for PdtKnxFloat {
    fn general(value: f32) -> Self {
        Self {
            code: "9.x".to_string(),
            unit: "".to_string(),
            value,
        }
    }
    fn get_value(&self) -> f32 {
        self.value
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Whatever> {
        let value = bytes_to_float(bytes)?;
        Ok(Self {
            code: "9.x".to_string(),
            unit: "".to_owned(),
            value,
        })
    }

    fn get_bytes(&self) -> Vec<u8> {
        calimero_float_to_bytes(self.value)
    }

    fn is_small(&self) -> bool {
        false
    }
}

impl PdtKnxFloat {
    pub fn temp(value: f32) -> Self {
        Self {
            code: "9.001".to_string(),
            unit: "°C".to_string(),
            value,
        }
    }

    pub fn temp_from_bytes(bytes: &[u8]) -> Result<Self, Whatever> {
        let value = bytes_to_float(bytes)?;
        Ok(Self::temp(value))
    }
}

fn _float_to_bytes(value: f32) -> Vec<u8> {
    let sign = value < 0.0;
    let v = value.abs();
    let v = v * 100.0;
    let m = v.floor();

    // Convert the decimal part to base 2
    //
    let mut f = v - m;
    let mut bits = 0u16;
    for i in 0..11 {
        f *= 2.0;
        if f >= 1.0 {
            bits |= 1 << (15 - i);
            f -= 1.0;
        }
    }

    let m = m as u32;
    // Combine real and decimal parts in a single u32
    // with decimal point at bit 16
    //
    let mantissa = m << 16 | bits as u32;

    let mut first_bit_set: i16 = 0;
    for i in (0..31).rev() {
        if (mantissa & 1 << i) > 0 {
            first_bit_set = i;
            break;
        }
    }
    // Exponent is how much we have to move the mantissa to have the first
    // bit inside the mantissa of the target f16 format
    //
    let exp = first_bit_set - 16 - 10;
    let mantissa: u32 = m << (31 - first_bit_set);

    let mut f16: u16 = 0;
    if sign {
        f16 = 0x8000;
    }
    f16 |= ((exp << 11) as u16) & 0b0111_1000_0000_0000;
    f16 |= (mantissa as u16 & 0b1111_1111_1110_0000) >> 5;
    Vec::from(f16.to_be_bytes())
}

// Implementation taken from java project calimero
// https://github.com/calimero-project/calimero-core/blob/d6fee46dbfeda9ddc90e77e25444dc1b1dd98f82/src/tuwien/auto/calimero/dptxlator/DPTXlator2ByteFloat.java#L300
//
fn calimero_float_to_bytes(v: f32) -> Vec<u8> {
    let mut v = v * 100.0;
    let mut exp = 0;
    while v < -2048.0 {
        v /= 2.0;
        exp += 1;
    }
    while v > 2048.0 {
        v /= 2.0;
        exp += 1;
    }

    let m = v.round() as i16 & 0x7ff;
    let mut msb: u8 = (exp << 3 | m >> 8) as u8;
    if v < 0.0 {
        msb |= 0x80;
    }
    let lsb = (m & 0xff) as u8;
    vec![msb, lsb]
}

fn bytes_to_float(bytes: &[u8]) -> Result<f32, Whatever> {
    let value = u16::from_be_bytes(match bytes.try_into() {
        Ok(v) => v,
        Err(e) => whatever!("Wrong bytes count, {:?}", e),
    });
    let sign = if value & 0x8000 > 0 { -1f32 } else { 1f32 };
    let mut exp = ((value & 0b0111_1000_0000_0000) >> 11) as i16;
    if (exp & 8) > 0 {
        exp -= 1;
        exp ^= 0xf;
        exp += -1;
    }
    let mut mantissa = value & 0x07ff;
    if sign < 0.0 {
        mantissa -= 1;
        mantissa ^= 0x7ff;
    }
    let mantissa: f32 = mantissa as f32 * sign;
    Ok((0.01 * mantissa) * (1 << exp) as f32)
}

pub struct PdtKnxByte {
    pub code: String,
    value: u8,
}

impl Pdt<u8> for PdtKnxByte {
    fn general(value: u8) -> Self {
        Self {
            code: "20.x".to_string(),
            value,
        }
    }

    fn get_value(&self) -> u8 {
        self.value
    }

    fn get_bytes(&self) -> Vec<u8> {
        vec![self.value]
    }

    fn from_bytes(b: &[u8]) -> Result<Self, Whatever>
    where
        Self: Sized,
    {
        let value = *b.get(0).with_whatever_context(|| "One byte is needes")?;
        Ok(Self {
            code: "20.x".to_string(),
            value,
        })
    }

    fn is_small(&self) -> bool {
        todo!()
    }
}

pub struct PdtKnxWord {
    pub code: String,
    value: u16,
}

impl Pdt<u16> for PdtKnxWord {
    fn general(value: u16) -> Self {
        Self {
            code: "7.x".to_string(),
            value,
        }
    }

    fn get_value(&self) -> u16 {
        self.value
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.value.to_be_bytes().to_vec()
    }

    fn from_bytes(b: &[u8]) -> Result<Self, Whatever>
    where
        Self: Sized,
    {
        let mut reader = Cursor::new(b);
        let value = reader.read_u16::<BigEndian>().with_whatever_context(|e| "Unable to get 2 bytes {e}")?;
        Ok(Self {
            code: "7.x".to_string(),
            value,
        })
    }

    fn is_small(&self) -> bool {
        false
    }
}

pub struct PdtKnxULong {
    pub code: String,
    value: u32,
}

impl Pdt<u32> for PdtKnxULong {
    fn general(value: u32) -> Self {
        Self {
            code: "12.x".to_string(),
            value,
        }
    }

    fn get_value(&self) -> u32 {
        self.value
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.value.to_be_bytes().to_vec()
    }

    fn from_bytes(b: &[u8]) -> Result<Self, Whatever>
    where
        Self: Sized,
    {
        let mut reader = Cursor::new(b);
        let value = reader.read_u32::<BigEndian>().with_whatever_context(|e| "Unable to get 4 bytes {e}")?;
        Ok(Self {
            code: "8.x".to_string(),
            value,
        })
    }

    fn is_small(&self) -> bool {
        false
    }
}

pub struct PdtKnxBit {
    pub code: String,
    value: bool,
}

impl Pdt<bool> for PdtKnxBit {
    fn general(value: bool) -> Self {
        Self {
            code: "1.x".to_string(),
            value,
        }
    }

    fn get_value(&self) -> bool {
        self.value
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Whatever> {
        let value = bytes.get(0).with_whatever_context(|| "Should have at least one byte")? > &0;
        Ok(Self {
            code: "1.x".to_string(),
            value,
        })
    }
    fn get_bytes(&self) -> Vec<u8> {
        vec![self.value as u8]
    }

    fn is_small(&self) -> bool {
        true
    }
}

impl PdtKnxBit {
    pub fn switch(value: bool) -> Self {
        Self {
            code: "1.001".to_string(),
            value,
        }
    }
}

pub struct PdtKnxB1U3 {
    pub code: String,
    bit: bool,
    step: u8,
}

impl Pdt<u8> for PdtKnxB1U3 {
    fn get_value(&self) -> u8 {
        let mut value: u8 = if self.bit { 8 } else { 0 };
        value |= self.step;
        value
    }

    fn get_bytes(&self) -> Vec<u8> {
        vec![self.get_value() as u8]
    }

    fn general(value: u8) -> Self {
        Self {
            code: "3.x".to_string(),
            bit: (value & 8) > 0,
            step: value & 0b111,
        }
    }

    fn from_bytes(b: &[u8]) -> Result<Self, Whatever>
    where
        Self: Sized,
    {
        let value = b.get(0).with_whatever_context(|| "Should have at least one byte")?;
        Ok(Self {
            code: "0.x".to_string(),
            bit: (value & 8) > 0,
            step: value & 0b111,
        })
    }

    fn is_small(&self) -> bool {
        true
    }
}

impl PdtKnxB1U3 {
    pub fn dimming(increase: bool, step: u8) -> Self {
        Self {
            code: "3.007".to_string(),
            bit: increase,
            step: step & 0b111,
        }
    }

    pub fn blinds(up: bool, step: u8) -> Self {
        Self {
            code: "3.008".to_string(),
            bit: up,
            step: step & 0b111,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() {
        let test_values = vec![0.0, -10.8, -0.01, 188.95999];

        for value in test_values.into_iter() {
            let bytes = calimero_float_to_bytes(value);
            let parsed_value = bytes_to_float(bytes.as_slice()).expect("Should be able to parse value");
            assert_eq!(value, parsed_value);
        }
    }
}
