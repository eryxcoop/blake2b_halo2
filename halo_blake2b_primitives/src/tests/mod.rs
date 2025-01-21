use super::*;
use crate::auxiliar_functions::*;
use halo2_proofs::halo2curves::bn256::Fr;

mod tests_8bits_addition;
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

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn new_for_addition_alone(addition_trace: [[Value<F>; 6]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            rotation_trace_24: Self::_unknown_trace_for_rotation_24(),
        }
    }

    fn new_for_rotation_24(rotation_trace_24: [[Value<F>; 5]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            rotation_trace_24,
        }
    }
}
