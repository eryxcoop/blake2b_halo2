use super::*;

#[derive(Clone, Debug)]
pub struct XorChip<F: Field> {
    pub decompose_8_chip: Decompose8Chip<F>,
    full_number_u64: Column<Advice>,
    limbs_8_bits: [Column<Advice>; 8],
    t_xor_left: TableColumn,
    t_xor_right: TableColumn,
    t_xor_out: TableColumn,
    q_xor: Selector,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> XorChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        limbs_8_bits: [Column<Advice>; 8],
        mut decompose_8_chip: Decompose8Chip<F>,
        full_number_u64: Column<Advice>,
    ) -> Self {
        let q_xor = meta.complex_selector();
        let t_xor_left = meta.lookup_table_column();
        let t_xor_right = meta.lookup_table_column();
        let t_xor_out = meta.lookup_table_column();

        for limb in limbs_8_bits {
            decompose_8_chip.range_check_for_limb_8_bits(meta, &limb);
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
            decompose_8_chip,
            full_number_u64,
            limbs_8_bits,
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
                // assign the table
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

    pub fn create_xor_region(
        &mut self,
        layouter: &mut impl Layouter<F>,
        xor_trace: [[Value<F>; 9]; 3],
    ) {
        let _ = layouter.assign_region(
            || "xor",
            |mut region| {
                let _ = self.q_xor.enable(&mut region, 0);

                let first_row = xor_trace[0].to_vec();
                let second_row = xor_trace[1].to_vec();
                let third_row = xor_trace[2].to_vec();

                self.decompose_8_chip
                    .assign_8bit_row_from_values(&mut region, first_row, 0);
                self.decompose_8_chip
                    .assign_8bit_row_from_values(&mut region, second_row, 1);
                self.decompose_8_chip
                    .assign_8bit_row_from_values(&mut region, third_row, 2);

                Ok(())
            },
        );
    }

    pub fn unknown_trace() -> [[Value<F>; 9]; 3] {
        [[Value::unknown(); 9]; 3]
    }
}
