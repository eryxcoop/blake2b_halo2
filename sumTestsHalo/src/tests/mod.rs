use super::*;
use crate::auxiliar_functions::*;
use halo2_proofs::halo2curves::bn256::Fr;

mod tests_addition_mod_64;
mod tests_rotation;
mod tests_xor;

pub fn valid_addition_trace() -> [[Value<Fr>; 6]; 3] {
    [
        [
            max_u64(),
            max_u16(),
            max_u16(),
            max_u16(),
            max_u16(),
            zero(),
        ],
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
