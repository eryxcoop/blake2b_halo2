use super::*;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Value};

#[derive(Default, Clone, Debug)]
pub struct LimbRotation;

/// This config does not have a gate. It only rotates the limbs of a number to the right and
/// uses copy constrains to ensure that the rotation is correct.
/// This config is used in our circuit to implement 16-bit, 24-bit and 32-bit rotations.
impl LimbRotation {
    pub fn unknown_trace<F: PrimeField>() -> [[Value<F>; 9]; 2] {
        [[Value::unknown(); 9]; 2]
    }

    /// This method receives a row of cells, and rotates the limbs to the right by the number
    /// specified in the limbs_to_rotate_to_the_right parameter. It then constrains the output
    /// to be the correct rotation of the input.
    /// For this method to work, the input_row must be the last row of the trace at the moment
    /// the method is called
    pub fn generate_rotation_rows_from_input_row<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        decompose_config: &mut impl Decomposition<8>,
        input_row: [AssignedCell<F, F>; 9],
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let result_value =
            Self::right_rotation_value(input_row[0].value(), limbs_to_rotate_to_the_right);
        // given the shifted value, I think it suffices to make equality constraints over the related limbs. However,
        // the decomposition gate also range check each limbs, which is over-constrained here.
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

    // [Zhiyong comment - answered] instead of computing again the limbs of shifted-rotation, how about copy-advice directly between the two
    // relevant limbs for input_row and result_row
    //
    // This object does not have access to the limbs, the only one who has it is the DecomposeConfig
    // so we preferred to avoid breaking encapsulation and just compute the limbs again (only
    // because computing the limbs is not an expensive operation)

    // how about: input_row[i].copy_advice(...), as we don't need a full decomposition_config (see the above comment)

    /// Here the rotation is enforced by copy constraints
    #[allow(clippy::ptr_arg)]
    pub fn constrain_result_with_input_row<F: PrimeField>(
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
    fn right_rotation_value<F: PrimeField>(value: Value<&F>, limbs_to_rotate: usize) -> Value<F> {
        value.map(|input| {
            let bits_to_rotate = limbs_to_rotate * 8;
            auxiliar_functions::rotate_right_field_element(*input, bits_to_rotate)
        })
    }
}
