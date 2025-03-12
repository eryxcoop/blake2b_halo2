use super::*;
use halo2_proofs::circuit::AssignedCell;

/// This config handles the 63-right-bit rotation of a 64-bit number, which is the same as the
/// 1-bit rotation to the left.
#[derive(Clone, Debug)]
pub struct Rotate63Config<F: Field, const T: usize, const R: usize> {
    q_rot63: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField, const T: usize, const R: usize> Rotate63Config<F, T, R> {
    pub fn configure(meta: &mut ConstraintSystem<F>, full_number_u64: Column<Advice>) -> Self {
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

        Self {
            _ph: PhantomData,
            q_rot63,
        }
    }

    /// Receives a trace and populates the rows for the rotation of 63 bits to the right
    // [Inigo comment] Where are you using this function? Is it only in tests? why is it public?
    pub fn populate_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_config: &mut impl Decomposition<F, T>,
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
    pub fn generate_rotation_rows_from_cells(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        input_row: [AssignedCell<F, F>; 9],
        decompose_config: &mut impl Decomposition<F, T>,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.q_rot63.enable(region, *offset)?;

        let input_value = input_row[0].value().copied();
        let result_value = input_value.map(|input| {
            auxiliar_functions::rotate_right_field_element(input, 63)
        });

        // Why do you decompose? can't you work directly on the rotation of the value?
        let result_cell =
            decompose_config.generate_row_from_value(region, result_value, *offset)?;
        *offset += 1;
        Ok(result_cell)
    }

    // functions that are only used in tests should not be part of the config.
    #[cfg(test)]
    fn unknown_trace() -> [[Value<F>; R]; 2] {
        [[Value::unknown(); R]; 2]
    }
}
