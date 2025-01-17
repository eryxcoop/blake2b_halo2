use ff::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;

pub fn trash() -> Value<Fr> {
    zero()
}
pub fn max_u64() -> Value<Fr> {
    Value::known(Fr::from(((1u128 << 64) - 1) as u64))
}
pub fn max_u16() -> Value<Fr> {
    let number = (1 << 16) - 1;
    value_for(number)
}

pub fn max_u24() -> Value<Fr> {
    known_value_from_number((1u128 << 24) - 1)
}
pub fn max_u8() -> Value<Fr> {
    Value::known(Fr::from((1 << 8) - 1))
}
pub fn max_u40() -> Value<Fr> {
    Value::known(Fr::from(((1u128 << 40) - 1) as u64))
}

pub fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
pub fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}

pub fn spread(mut n: u16) -> u32 {
    let mut spread: u32 = 0;
    let mut position: u32 = 0;

    while n != 0 {
        // Extract the least significant bit
        let bit: u32 = (n & 1u16) as u32;
        // Shift it to the appropriate position in the spread number
        spread |= bit << (2 * position);
        // Move to the next bit of the input number
        n >>= 1;
        // Increment the spread position
        position += 1;
    }

    spread
}

pub fn value_for(number: u64) -> Value<Fr> {
    Value::known(Fr::from(number))
}

pub fn known_value_from_number(number: u128) -> Value<Fr> {
    Value::known(Fr::from(number as u64))
}
