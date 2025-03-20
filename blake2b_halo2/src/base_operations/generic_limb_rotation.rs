use super::*;
use ff::{PrimeField};
use halo2_proofs::circuit::{AssignedCell, Value};
use crate::base_operations::decompose_8::Decompose8Config;

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
        decompose_config: &mut Decompose8Config,
        input_row: [AssignedCell<F, F>; 9],
        limbs_to_rotate_to_the_right: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let result_value = Self::right_rotation_value(input_row[0].value(), limbs_to_rotate_to_the_right);
        let result_cell = region.assign_advice(
            ||"Full number rotation output",
            decompose_config.get_full_number_u64_column(),
            *offset,
            || result_value
        )?;
        decompose_config.q_decompose.enable(region, *offset)?;

        for i in 0..8 {
            // We must subtract limb_rotations_right because if a number is expressed bitwise
            // as x = l1|l2|...|l7|l8, the limbs are stored as [l8, l7, ..., l2, l1]
            let top_assigned_cell = input_row[i + 1].clone();
            let out_limb_index = (8 + i - limbs_to_rotate_to_the_right) % 8;
            top_assigned_cell.copy_advice(
                || "Limb rotation output",
                region,
                decompose_config.get_limb_column(out_limb_index),
                *offset
            )?;
        }

        *offset += 1;
        Ok(result_cell)
    }

    /// Computes the actual value of the rotation of the number
    fn right_rotation_value<F: PrimeField>(value: Value<&F>, limbs_to_rotate: usize) -> Value<F> {
        value.map(|input| {
            let bits_to_rotate = limbs_to_rotate * 8;
            auxiliar_functions::rotate_right_field_element(*input, bits_to_rotate)
        })
    }
}
