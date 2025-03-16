use super::*;
use halo2_proofs::circuit::AssignedCell;

/// This config handles the 63-right-bit rotation of a 64-bit number, which is the same as the
/// 1-bit rotation to the left.
// should better documented regarding the legitimate field size for this special chip
#[derive(Clone, Debug)]
pub struct Rotate63Config<const T: usize, const R: usize> {
    q_rot63: Selector,
}

impl<const T: usize, const R: usize> Rotate63Config<T, R> {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
    ) -> Self {
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

    /// Receives a trace and populates the rows for the rotation of 63 bits to the right
    // [Inigo comment - answered] Where are you using this function? Is it only in tests? why is it public?
    //
    // This function is used for testing. We use it to be able to have tests that checks that the
    // gate is correctly defined. If we use the generate_rotation_rows_from_cells, we wouldn't be able
    // to fill the circuit with incorrect values and check that the proof is rejected.
    // We need to make it public to be able to call it from the tests.

    // how about adding `enforce_modulus_size::<F>();` within this chip to keep the generic chip implementation clean?
    pub fn populate_rotation_rows<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_config: &mut impl Decomposition<T>,
        trace: [[Value<F>; R]; 2],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rotate 63",
            |mut region| {
                let first_row = trace[0].to_vec();
                let second_row = trace[1].to_vec();
                decompose_config.populate_row_from_values(&mut region, first_row.clone(), 0)?;
                decompose_config.populate_row_from_values(&mut region, second_row.clone(), 1)?;
                self.q_rot63.enable(&mut region, 1)
            },
        )?;
        Ok(())
    }

    /// Receives a row of cells, generates a row for the rotation of 63 bits to the right
    /// and populates the circuit with it
    // as the configure only invovles two cells of one column, the assignment should be done for cells?
    pub fn generate_rotation_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input_row: [AssignedCell<F, F>; 9],
        decompose_config: &mut impl Decomposition<T>,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.q_rot63.enable(region, *offset)?;

        let result_value = input_row[0]
            .value()
            .map(|input| auxiliar_functions::rotate_right_field_element(*input, 63));

        // Why do you decompose? can't you work directly on the rotation of the value?
        let result_cell =
            decompose_config.generate_row_from_value(region, result_value, *offset)?;
        *offset += 1;
        Ok(result_cell)
    }
}
