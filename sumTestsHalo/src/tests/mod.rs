use super::*;
use halo2_proofs::halo2curves::bn256::Fr;

mod tests_addition_mod_64;
mod tests_rotation;

fn max_u64() -> Value<Fr> {
    Value::known(Fr::from(((1u128 << 64) - 1) as u64))
}
fn max_u16() -> Value<Fr> {
    Value::known(Fr::from((1 << 16) - 1))
}
fn max_u24() -> Value<Fr> {
    known_value_from_number((1u128 << 24) - 1)
}
fn max_u8() -> Value<Fr> {
    Value::known(Fr::from((1 << 8) - 1))
}
fn max_u40() -> Value<Fr> {
    Value::known(Fr::from(((1u128 << 40) - 1) as u64))
}

fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}

pub fn valid_addition_trace() -> [[Value<Fr>; 6]; 3] {
    [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16(), zero()],
        [one(), one(), zero(), zero(), zero(), zero()],
        [zero(), zero(), zero(), zero(), zero(), one()],
    ]
}

pub fn valid_rotation_trace_63() -> [[Value<Fr>; 5]; 2] {
    [
        [one(), one(), zero(), zero(), zero()],
        [one() + one(), one() + one(), zero(), zero(), zero()],
    ]
}

fn known_value_from_number(number: u128) -> Value<Fr> {
    Value::known(Fr::from(number as u64))
}
