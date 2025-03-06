use super::*;
use crate::chips::decompose_8::Decompose8Config;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct LimbRotationConfig<F: Field> {
    _ph: PhantomData<F>,
}

/// This config does not have a gate. It only rotates the limbs of a number to the right and
/// uses copy constrains to ensure that the rotation is correct.
/// This config is used in our circuit to implement 16-bit, 24-bit and 32-bit rotations.
#[allow(clippy::new_without_default)]
impl<F: PrimeField> LimbRotationConfig<F> {
    pub fn new() -> Self {
        Self { _ph: PhantomData }
    }

    pub fn unknown_trace() -> [[Value<F>; 9]; 2] {
        [[Value::unknown(); 9]; 2]
    }

    /// This method is meant to receive a valid rotation_trace, and populate the circuit with it
    /// The rotation trace is a matrix with 2 rows and 9 columns. The rows represent the input
    /// and output of the rotation, and the columns represent the limbs of each number.
    /// In the end of the method, the circuit will have the correct constraints to ensure that
    /// the output is the input rotated to the right by the number of limbs specified in the
    /// limb_rotations_right parameter.
    pub fn populate_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_config: &mut Decompose8Config<F>,
        trace: [[Value<F>; 9]; 2],
        limb_rotations_right: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || format!("rotate {}", limb_rotations_right),
            |mut region| {
                let first_row =
                    decompose_config.populate_row_from_values(&mut region, trace[0].to_vec(), 0)?;
                let second_row =
                    decompose_config.populate_row_from_values(&mut region, trace[1].to_vec(), 1)?;

                Self::constrain_result_with_input_row(
                    &mut region,
                    &first_row,
                    &second_row,
                    limb_rotations_right,
                )?;
                Ok(())
            },
        )?;
        Ok(())
    }

    /// This method receives a value, and copies it to the trace. Then calls another method to
    /// do the rotation
    pub fn generate_rotation_rows_from_value(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        decompose_config: &mut impl Decomposition<F, 8>,
        input: Value<F>,
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let input_row =
            decompose_config.generate_row_from_value_and_keep_row(region, input, *offset)?;
        *offset += 1;

        self.generate_rotation_rows_from_input_row(
            region,
            offset,
            decompose_config,
            input_row.try_into().unwrap(),
            limbs_to_rotate_to_the_right,
        )
    }

    /// This method receives a row of cells, and rotates the limbs to the right by the number
    /// specified in the limbs_to_rotate_to_the_right parameter. It then constrains the output
    /// to be the correct rotation of the input.
    /// For this method to work, the input_row must be the last row of the trace at the moment
    /// the method is called
    pub fn generate_rotation_rows_from_input_row(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        decompose_config: &mut impl Decomposition<F, 8>,
        input_row: [AssignedCell<F, F>; 9],
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let value = input_row[0].value().copied();
        let result_value = Self::right_rotation_value(value, limbs_to_rotate_to_the_right);

        let result_row =
            decompose_config.generate_row_from_value_and_keep_row(region, result_value, *offset)?;
        *offset += 1;

        #[allow(clippy::unnecessary_fallible_conversions)]
        Self::constrain_result_with_input_row(
            region,
            &(input_row.try_into().unwrap()),
            &result_row,
            limbs_to_rotate_to_the_right,
        )?;

        let result_cell = result_row[0].clone();
        Ok(result_cell)
    }

    /// Here the rotation is enforced by copy constraints
    #[allow(clippy::ptr_arg)]
    fn constrain_result_with_input_row(
        region: &mut Region<F>,
        input_row: &Vec<AssignedCell<F, F>>,
        result_row: &Vec<AssignedCell<F, F>>,
        limbs_to_rotate: usize,
    ) -> Result<(), Error> {
        for i in 0..8 {
            // We must subtract limb_rotations_right because if a number is expressed bitwise
            // as x = l1|l2|...|l7|l8, the limbs are stored as [l8, l7, ..., l2, l1]
            let top_cell = input_row[i + 1].cell();
            let bottom_cell = result_row[((8 + i - limbs_to_rotate) % 8) + 1].cell();
            region.constrain_equal(top_cell, bottom_cell)?;
        }
        Ok(())
    }

    /// Computes the actual value of the rotation of the number
    fn right_rotation_value(value: Value<F>, limbs_to_rotate: usize) -> Value<F> {
        value.and_then(|input| {
            let bits_to_rotate = limbs_to_rotate * 8;
            Value::known(auxiliar_functions::rotate_right_field_element(input, bits_to_rotate))
        })
    }
}
