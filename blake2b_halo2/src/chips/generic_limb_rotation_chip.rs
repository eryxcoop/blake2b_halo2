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
    /// This chip does not have a gate. It only rotates the limbs of a number to the right and
    /// uses copy constrains to ensure that the rotation is correct.

    pub fn new() -> Self {
        Self { _ph: PhantomData }
    }

    pub fn unknown_trace() -> [[Value<F>; 9]; 2] {
        [[Value::unknown(); 9]; 2]
    }

    pub fn populate_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_chip: &mut Decompose8Chip<F>,
        trace: [[Value<F>; 9]; 2],
        limb_rotations_right: usize,
    ) {
        /// This method is meant to receive a valid rotation_trace, and populate the circuit with it
        /// The rotation trace is a matrix with 2 rows and 9 columns. The rows represent the input
        /// and output of the rotation, and the columns represent the limbs of each number.
        /// In the end of the method, the circuit will have the correct constraints to ensure that
        /// the output is the input rotated to the right by the number of limbs specified in the
        /// limb_rotations_right parameter.
        let _ = layouter.assign_region(
            || format!("rotate {}", limb_rotations_right),
            |mut region| {
                let first_row = decompose_chip
                    .populate_row_from_values(&mut region, trace[0].to_vec(), 0)
                    .unwrap();
                let second_row = decompose_chip
                    .populate_row_from_values(&mut region, trace[1].to_vec(), 1)
                    .unwrap();

                Self::_constrain_result_with_input_row(&mut region, &first_row, &second_row, limb_rotations_right)?;
                Ok(())
            },
        );
    }

    pub fn generate_rotation_rows_from_value(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        decompose_chip: &mut impl Decomposition<F, 8>,
        input: Value<F>,
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        /// This method receives a value, and copies it to the trace. Then calls another method to
        /// do the rotation
        let input_row = decompose_chip.generate_row_from_value_and_keep_row(
            region, input, *offset)?;
        *offset += 1;

        self.generate_rotation_rows_from_input_row(
            region,
            offset,
            decompose_chip,
            input_row.try_into().unwrap(),
            limbs_to_rotate_to_the_right,
        )
    }

    pub fn generate_rotation_rows_from_input_row(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        decompose_chip: &mut impl Decomposition<F, 8>,
        input_row: [AssignedCell<F, F>; 9],
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        /// This method receives a row of cells, and rotates the limbs to the right by the number
        /// specified in the limbs_to_rotate_to_the_right parameter. It then constrains the output
        /// to be the correct rotation of the input.
        /// For this method to work, the input_row must be the last row of the trace at the moment
        /// the method is called
        let value = input_row[0].value().copied();
        let result_value = Self::_right_rotation_value(value, limbs_to_rotate_to_the_right);

        let result_row = decompose_chip.generate_row_from_value_and_keep_row(
            region,
            result_value,
            *offset,
        )?;
        *offset += 1;

        Self::_constrain_result_with_input_row(region, &(input_row.try_into().unwrap()), &result_row, limbs_to_rotate_to_the_right)?;

        let result_cell = result_row[0].clone();
        Ok(result_cell)
    }

    fn _constrain_result_with_input_row(region: &mut Region<F>, input_row: &Vec<AssignedCell<F, F>>, result_row: &Vec<AssignedCell<F, F>>, limbs_to_rotate: usize) -> Result<(), Error> {
        for i in 0..8 {
            // We must subtract limb_rotations_right because if a number is expressed bitwise
            // as x = l1|l2|...|l7|l8, the limbs are stored as [l8, l7, ..., l2, l1]
            let top_cell = input_row[i + 1].cell();
            let bottom_cell =
                result_row[((8 + i - limbs_to_rotate) % 8) + 1].cell();
            region.constrain_equal(top_cell, bottom_cell)?;
        }
        Ok(())
    }

    fn _right_rotation_value(value: Value<F>, limbs_to_rotate: usize) -> Value<F> {
        let result_value = value.and_then(|input| {
            Value::known(auxiliar_functions::rotate_right_field_element(
                input,
                limbs_to_rotate * 8,
            ))
        });
        result_value
    }
}

