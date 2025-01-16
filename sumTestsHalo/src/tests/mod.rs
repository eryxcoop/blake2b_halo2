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

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn new_for_addition_alone(addition_trace: [[Value<F>; 6]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            addition_trace,
            rotation_trace_63: Self::_unknown_trace_for_rotation_63(), // TODO: check this
            rotation_trace_24: Self::_unknown_trace_for_rotation_24(),
            xor_trace: Self::_unknown_trace_for_xor(),
            should_create_xor_table: false,
        }
    }

    fn new_for_rotation_63(rotation_trace_63: [[Value<F>; 5]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            addition_trace: Self::_unknown_trace_for_addition(),
            rotation_trace_63,
            rotation_trace_24: Self::_unknown_trace_for_rotation_24(),
            xor_trace: Self::_unknown_trace_for_xor(),
            should_create_xor_table: false,
        }
    }

    fn new_for_rotation_24(rotation_trace_24: [[Value<F>; 5]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            addition_trace: Self::_unknown_trace_for_addition(),
            rotation_trace_63: Self::_unknown_trace_for_rotation_63(),
            rotation_trace_24,
            xor_trace: Self::_unknown_trace_for_xor(),
            should_create_xor_table: false,
        }
    }

    fn new_for_xor_alone(xor_trace: [[Value<F>; 9]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            addition_trace: Self::_unknown_trace_for_addition(),
            rotation_trace_63: Self::_unknown_trace_for_rotation_63(),
            rotation_trace_24: Self::_unknown_trace_for_rotation_24(),
            xor_trace,
            should_create_xor_table: true,
        }
    }
}
