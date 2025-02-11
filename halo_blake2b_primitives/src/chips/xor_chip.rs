use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use halo2_proofs::circuit::AssignedCell;

#[derive(Clone, Debug)]
pub struct XorChip<F: PrimeField> {
    t_xor_left: TableColumn,
    t_xor_right: TableColumn,
    t_xor_out: TableColumn,
    q_xor: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> XorChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, limbs_8_bits: [Column<Advice>; 8]) -> Self {
        let q_xor = meta.complex_selector();
        let t_xor_left = meta.lookup_table_column();
        let t_xor_right = meta.lookup_table_column();
        let t_xor_out = meta.lookup_table_column();

        for limb in limbs_8_bits {
            meta.lookup(format!("xor lookup limb {:?}", limb), |meta| {
                let left: Expression<F> = meta.query_advice(limb, Rotation::cur());
                let right: Expression<F> = meta.query_advice(limb, Rotation::next());
                let out: Expression<F> = meta.query_advice(limb, Rotation(2));
                let q_xor = meta.query_selector(q_xor);
                vec![
                    (q_xor.clone() * left, t_xor_left),
                    (q_xor.clone() * right, t_xor_right),
                    (q_xor.clone() * out, t_xor_out),
                ]
            });
        }

        Self {
            t_xor_left,
            t_xor_right,
            t_xor_out,
            q_xor,
            _ph: PhantomData,
        }
    }

    pub fn populate_xor_lookup_table(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let table_name = "xor check table";

        layouter.assign_table(
            || table_name,
            |mut table| {
                for left in 0..256 {
                    for right in 0..256 {
                        let index = left * 256 + right;
                        let result = left ^ right;
                        table.assign_cell(
                            || "left_value",
                            self.t_xor_left,
                            index,
                            || Value::known(F::from(left as u64)),
                        )?;
                        table.assign_cell(
                            || "right_value",
                            self.t_xor_right,
                            index,
                            || Value::known(F::from(right as u64)),
                        )?;
                        table.assign_cell(
                            || "out_value",
                            self.t_xor_out,
                            index,
                            || Value::known(F::from(result as u64)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn populate_xor_region(
        &mut self,
        layouter: &mut impl Layouter<F>,
        xor_trace: [[Value<F>; 9]; 3],
        decompose_8_chip: &mut Decompose8Chip<F>,
    ) {
        // This method receives a trace and just assigns it to the circuit
        let _ = layouter.assign_region(
            || "xor",
            |mut region| {
                let _ = self.q_xor.enable(&mut region, 0);

                let first_row = xor_trace[0].to_vec();
                let second_row = xor_trace[1].to_vec();
                let third_row = xor_trace[2].to_vec();

                decompose_8_chip.populate_row_from_values(&mut region, first_row, 0);
                decompose_8_chip.populate_row_from_values(&mut region, second_row, 1);
                decompose_8_chip.populate_row_from_values(&mut region, third_row, 2);

                Ok(())
            },
        );
    }

    pub fn generate_xor_rows(
        &mut self,
        layouter: &mut impl Layouter<F>,
        value_a: Value<F>,
        value_b: Value<F>,
        decompose_8_chip: &mut Decompose8Chip<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "xor",
            |mut region| {
                let _ = self.q_xor.enable(&mut region, 0);

                let result_value = value_a.and_then(|v0| {
                    value_b
                        .and_then(|v1| Value::known(auxiliar_functions::xor_field_elements(v0, v1)))
                });

                decompose_8_chip.generate_row_from_value(&mut region, value_a, 0)?;
                decompose_8_chip.generate_row_from_value(&mut region, value_b, 1)?;
                let result_cell =
                    decompose_8_chip.generate_row_from_value(&mut region, result_value, 2)?;

                Ok(result_cell)
            },
        )
    }

    pub fn generate_xor_rows_from_cells(
        &mut self,
        layouter: &mut impl Layouter<F>,
        cell_a: AssignedCell<F, F>,
        cell_b: AssignedCell<F, F>,
        decompose_8_chip: &mut Decompose8Chip<F>,
    ) -> Result<[AssignedCell<F, F>; 9], Error> {
        let value_a = cell_a.value().copied();
        let value_b = cell_b.value().copied();

        layouter.assign_region(
            || "xor",
            |mut region| {
                let _ = self.q_xor.enable(&mut region, 0);

                let result_value = value_a.and_then(|v0| {
                    value_b
                        .and_then(|v1| Value::known(auxiliar_functions::xor_field_elements(v0, v1)))
                });

                decompose_8_chip.generate_row_from_cell(&mut region, cell_a.clone(), 0)?;
                decompose_8_chip.generate_row_from_cell(&mut region, cell_b.clone(), 1)?;

                let result_row = decompose_8_chip
                    .generate_row_from_value_and_keep_row(&mut region, result_value, 2)
                    .unwrap();

                let result_row_array = result_row.try_into().unwrap();
                Ok(result_row_array)
            },
        )
    }

    pub fn unknown_trace() -> [[Value<F>; 9]; 3] {
        [[Value::unknown(); 9]; 3]
    }
}
