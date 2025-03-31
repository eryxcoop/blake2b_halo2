use crate::types::Blake2bWord;
use ff::PrimeField;

pub(crate) fn field_for<T, F>(number: T) -> F
where
    T: Into<u128>,
    F: PrimeField,
{
    F::from_u128(number.into())
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