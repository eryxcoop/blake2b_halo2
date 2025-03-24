use super::*;
use crate::types::AssignedNative;
use num_bigint::BigUint;

/// This config handles the 63-right-bit rotation of a 64-bit number, which is the same as the
/// 1-bit rotation to the left.
/// For the gate of this config to be sound, it is necessary that the modulus of the field is
/// greater than 2^65.
#[derive(Clone, Debug)]
pub struct Rotate63Config<const T: usize, const R: usize> {
    pub q_rot63: Selector,
}

impl<const T: usize, const R: usize> Rotate63Config<T, R> {
    pub fn configure<F: PrimeField>(
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

    /// Receives a row of cells, generates a row for the rotation of 63 bits to the right
    /// and populates the circuit with it
    pub fn generate_rotation_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &AssignedNative<F>,
        decompose_config: &mut impl Decomposition,
    ) -> Result<AssignedNative<F>, Error> {
        self.q_rot63.enable(region, *offset)?;
        let result_value =
            input.value().map(|input| auxiliar_functions::rotate_right_field_element(*input, 63));
        let result_cell = region.assign_advice(
            || "Rotate63 output",
            decompose_config.get_full_number_u64_column(),
            *offset,
            || result_value,
        )?;
        *offset += 1;
        Ok(result_cell)
    }

    /// Enforces the field's modulus to be greater than 2^65
    pub fn enforce_modulus_size<F: PrimeField>() {
        let modulus_bytes: Vec<u8> = hex::decode(F::MODULUS.trim_start_matches("0x"))
            .expect("Modulus is not a valid hex number");
        let modulus = BigUint::from_bytes_be(&modulus_bytes);
        let two_pow_65 = BigUint::from(1u128 << 65);
        assert!(modulus > two_pow_65, "Field modulus must be greater than 2^65");
    }
}
