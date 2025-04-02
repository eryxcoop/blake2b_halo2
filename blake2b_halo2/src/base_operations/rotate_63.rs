use super::*;
use num_bigint::BigUint;
use crate::base_operations::decompose_8::AssignedBlake2bWord;

/// This config handles the 63-right-bit rotation of a 64-bit number, which is the same as the
/// 1-bit rotation to the left.
/// For the gate of this config to be sound, it is necessary that the modulus of the field is
/// greater than 2^65.
#[derive(Clone, Debug)]
pub(crate) struct Rotate63Config {
    pub q_rot63: Selector,
}

impl Rotate63Config {
    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
    ) -> Self {
        Self::enforce_modulus_size::<F>();

        let q_rot63 = meta.complex_selector();
        /// The gate that will be used to rotate a number 63 bits to the right
        /// The gate is defined as:
        ///    0 = 2 * input_full_number - output_full_number
        ///                      * (2 * input_full_number - output_full_number - (1 << 64 - 1))
        meta.create_gate("rotate right 63", |meta| {
            let q_rot63 = meta.query_selector(q_rot63);
            let input_full_number = meta.query_advice(full_number_u64, Rotation(-1));
            let output_full_number = meta.query_advice(full_number_u64, Rotation(0));
            vec![
                q_rot63
                    * (Expression::Constant(F::from(2)) * input_full_number.clone()
                        - output_full_number.clone())
                    * (Expression::Constant(F::from(2)) * input_full_number
                        - output_full_number
                        - Expression::Constant(F::from(((1u128 << 64) - 1) as u64))),
            ]
        });

        Self { q_rot63 }
    }

    /// This method receives a [AssignedBlake2bWord] and a [full_number_u64] column where it will be
    /// copied. In the same column, the result is placed in the next row. The gate constrains the
    /// result.
    pub(crate) fn generate_rotation_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &AssignedBlake2bWord<F>,
        full_number_u64: Column<Advice>,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.q_rot63.enable(region, *offset)?;
        let result_value = input.value().map(|input| rotate_right_field_element(input, 63));

        let assigned_cell = region.assign_advice(
            || "Rotate63 output",
            full_number_u64,
            *offset,
            || result_value,
        )?;
        let result_cell = AssignedBlake2bWord(assigned_cell);
        *offset += 1;
        Ok(result_cell)
    }

    /// Enforces the field's modulus to be greater than 2^65. This is necessary to preserve the
    /// soundness of a circuit that uses this operation.
    pub(crate) fn enforce_modulus_size<F: PrimeField>() {
        let modulus_bytes: Vec<u8> = hex::decode(F::MODULUS.trim_start_matches("0x"))
            .expect("Modulus is not a valid hex number");
        let modulus = BigUint::from_bytes_be(&modulus_bytes);
        let two_pow_65 = BigUint::from(1u128 << 65);
        assert!(modulus > two_pow_65, "Field modulus must be greater than 2^65");
    }
}
