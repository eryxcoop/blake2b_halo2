use super::*;
use halo2_proofs::circuit::AssignedCell;

#[derive(Clone, Debug)]
pub struct Rotate63Chip<F: Field, const T: usize, const R: usize> {
    q_rot63: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField, const T: usize, const R: usize> Rotate63Chip<F, T, R> {
    pub fn configure(meta: &mut ConstraintSystem<F>, full_number_u64: Column<Advice>) -> Self {
        let q_rot63 = meta.complex_selector();
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

    pub fn assign_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_chip: &mut impl Decomposition<F, T>,
        trace: [[Value<F>; R]; 2],
    ) {
        let _ = layouter.assign_region(
            || "rotate 63",
            |mut region| {

                let first_row = trace[0].to_vec();
                let second_row = trace[1].to_vec();
                decompose_chip.populate_row_from_values(&mut region, first_row.clone(), 0);
                decompose_chip.populate_row_from_values(&mut region, second_row.clone(), 1);
                let _ = self.q_rot63.enable(&mut region, 1);
                Ok(())
            },
        );
    }

    pub fn generate_rotation_rows_from_cells(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        input_row: [AssignedCell<F, F>; 9],
        decompose_chip: &mut impl Decomposition<F, T>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let _ = self.q_rot63.enable(region, *offset);

        let input_value = input_row[0].value().copied();
        let result_value = input_value.and_then(|input| {
            Value::known(auxiliar_functions::rotate_right_field_element(input, 63))
        });

        let result_cell =
            decompose_chip.generate_row_from_value(region, result_value, *offset)?;
        *offset += 1;
        Ok(result_cell)
    }

    pub fn unknown_trace() -> [[Value<F>; R]; 2] {
        [[Value::unknown(); R]; 2]
    }
}
