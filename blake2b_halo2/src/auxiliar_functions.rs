use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use crate::types::{Blake2bWord};

pub(crate) fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
pub(crate) fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}

pub(crate) fn blake2b_value_for(number: u64) -> Value<Blake2bWord> {
    Value::known(Blake2bWord(number))
}

pub(crate) fn value_for<T, F>(number: T) -> Value<F>
where
    T: Into<u128>,
    F: PrimeField,
{
    Value::known(field_for(number))
}

pub(crate) fn field_for<T, F>(number: T) -> F
where
    T: Into<u128>,
    F: PrimeField,
{
    let number: u128 = number.into();
    let lo: u64 = (number % (1u128 << 64)) as u64;
    let hi: u64 = (number / (1u128 << 64)) as u64;
    let field_pow64 = F::from(1 << 63) * F::from(2);
    F::from(hi) * field_pow64 + F::from(lo)
}

pub(crate) fn generate_row_8bits<T, F>(number: T) -> [Value<F>; 9]
where
    F: PrimeField,
    T: Into<u128>,
{
    let mut number: u128 = number.into();
    let mut ans = [Value::unknown(); 9];
    ans[0] = value_for(number);
    for ans_item in ans.iter_mut().take(9).skip(1) {
        *ans_item = value_for(number % 256);
        number /= 256;
    }
    ans
}

pub(crate) fn rotate_right_field_element(
    value_to_rotate: Blake2bWord,
    rotation_degree: usize,
) -> Blake2bWord {
    let value_to_rotate = value_to_rotate.0;
    let rotation_degree = rotation_degree % 64;
    let rotated_value = ((value_to_rotate as u128) >> rotation_degree)
        | ((value_to_rotate as u128) << (64 - rotation_degree));
    Blake2bWord(rotated_value as u64)
}