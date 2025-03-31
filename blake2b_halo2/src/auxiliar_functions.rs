use crate::types::Blake2bWord;
use ff::PrimeField;

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