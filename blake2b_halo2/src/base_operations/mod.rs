use crate::types::blake2b_word::Blake2bWord;
use super::*;

pub mod addition_mod_64;
pub mod decompose_8;
pub mod negate;
pub mod xor;

pub mod generic_limb_rotation;
pub mod rotate_63;

pub(crate) fn rotate_right_field_element(
    value_to_rotate: Blake2bWord,
    rotation_degree: usize,
) -> Blake2bWord {
    let value_to_rotate = value_to_rotate.0;
    let rotation_degree = rotation_degree % 64;
    let rotated_value = ((value_to_rotate as u128) >> rotation_degree)
        | ((value_to_rotate as u128) << (64 - rotation_degree));
    (rotated_value as u64).into()
}
