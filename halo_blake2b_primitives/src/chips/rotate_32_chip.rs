use std::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{Layouter, Value};
use crate::chips::decompose_8_chip::Decompose8Chip;

#[derive(Clone, Debug)]
pub struct Rotate32Chip<F: Field> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Rotate32Chip<F> {
    pub fn new() -> Self {
        Self {_ph: PhantomData}
    }

    pub fn unknown_trace() -> [[Value<F>; 9]; 2] {
        [[Value::unknown(); 9]; 2]
    }

    pub fn assign_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_chip: &mut Decompose8Chip<F>,
        trace: [[Value<F>; 9]; 2],
    ){
        let _ = layouter.assign_region(
            || "rotate 32",
            |mut region| {

                decompose_chip.assign_8bit_row_from_values(&mut region, trace[0].to_vec(), 0);
                decompose_chip.assign_8bit_row_from_values(&mut region, trace[1].to_vec(), 1);

                Ok(())
            },
        );
    }
}