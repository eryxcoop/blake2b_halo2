use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct LimbRotationChip<F: Field> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> LimbRotationChip<F> {
    pub fn new() -> Self {
        Self { _ph: PhantomData }
    }

    pub fn unknown_trace() -> [[Value<F>; 9]; 2] {
        [[Value::unknown(); 9]; 2]
    }

    pub fn assign_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_chip: &mut Decompose8Chip<F>,
        trace: [[Value<F>; 9]; 2],
        limb_rotations_right: usize,
    ) {
        let _ = layouter.assign_region(
            || format!("rotate {}", limb_rotations_right),
            |mut region| {
                let first_row = decompose_chip
                    .populate_row_from_values(&mut region, trace[0].to_vec(), 0)
                    .unwrap();
                let second_row = decompose_chip
                    .populate_row_from_values(&mut region, trace[1].to_vec(), 1)
                    .unwrap();

                for i in 0..7 {
                    let top_cell = first_row[i].cell();
                    let bottom_cell = second_row[(i + limb_rotations_right) % 8].cell();
                    region.constrain_equal(top_cell, bottom_cell)?;
                }

                Ok(())
            },
        );
    }

    pub fn generate_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_chip: &mut impl Decomposition<F, 8>,
        input: Value<F>,
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || format!("Rotate {} limbs", limbs_to_rotate_to_the_right),
            |mut region| {
                let result_value = input.and_then(|input| {
                    Value::known(auxiliar_functions::rotate_right_field_element(
                        input,
                        limbs_to_rotate_to_the_right * 8,
                    ))
                });

                decompose_chip.generate_row_from_value(&mut region, input, 0)?;
                let result_cell =
                    decompose_chip.generate_row_from_value(&mut region, result_value, 1)?;

                Ok(result_cell)
            },
        )
    }
}

impl<F: PrimeField> Default for LimbRotationChip<F> {
    fn default() -> Self {
        Self::new()
    }
}
