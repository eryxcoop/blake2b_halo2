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
fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}
fn two_power_48() -> Value<Fr> { Value::known(Fr::from(1 << 48)) }

fn valid_addition_trace() -> [[Value<Fr>; 6]; 3] {
    [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16(), zero()],
        [one(), one(), zero(), zero(), zero(), zero()],
        [zero(), zero(), zero(), zero(), zero(), one()],
    ]
}

fn valid_rotation_trace() -> [[Value<Fr>; 5]; 2] {
    [
        [one(), one(), zero(), zero(), zero()],
        [one() + one(), one() + one(), zero(), zero(), zero()],
    ]
}