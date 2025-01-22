use super::*;

#[derive(Clone, Debug)]
pub struct Decompose16Chip<F: Field> {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 4],
    q_decompose: Selector,
    t_range16: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Decompose16Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 4],
    ) -> Self {
        let q_decompose = meta.complex_selector();
        let t_range16 = meta.lookup_table_column();

        meta.create_gate("decompose in 16bit words", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let limbs: Vec<Expression<F>> = limbs
                .iter()
                .map(|column| meta.query_advice(*column, Rotation::cur()))
                .collect();
            vec![
                q_decompose
                    * (full_number
                        - limbs[0].clone()
                        - limbs[1].clone() * Expression::Constant(F::from(1 << 16))
                        - limbs[2].clone() * Expression::Constant(F::from(1 << 32))
                        - limbs[3].clone() * Expression::Constant(F::from(1 << 48))),
            ]
        });

        Self {
            full_number_u64,
            q_decompose,
            limbs,
            t_range16,
            _ph: PhantomData,
        }
    }

    pub fn assign_16bit_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) {
        let _ = self.q_decompose.enable(region, offset);
        let _ = region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0]);
        let _ = region.assign_advice(|| "limb0", self.limbs[0], offset, || row[1]);
        let _ = region.assign_advice(|| "limb1", self.limbs[1], offset, || row[2]);
        let _ = region.assign_advice(|| "limb2", self.limbs[2], offset, || row[3]);
        let _ = region.assign_advice(|| "limb3", self.limbs[3], offset, || row[4]);
    }

    pub fn range_check_for_limbs(&self, meta: &mut ConstraintSystem<F>) {
        for limb in self.limbs {
            Self::range_check_for_limb_16_bits(meta, &limb, self.q_decompose, self.t_range16);
        }
    }

    fn range_check_for_limb_16_bits(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_decompose: Selector,
        t_range16: TableColumn,
    ) {
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_decompose = meta.query_selector(q_decompose);
            vec![(q_decompose * limb, t_range16)]
        });
    }

    pub fn populate_lookup_table16(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let table_name = "range 16bit check table";
        let max_value = 1 << 16;
        self.fill_lookup_table(layouter, table_name, max_value)?;

        Ok(())
    }

    fn fill_lookup_table(
        &self,
        layouter: &mut impl Layouter<F>,
        table_name: &str,
        max_value: usize,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || table_name,
            |mut table| {
                // assign the table
                for i in 0..max_value {
                    table.assign_cell(
                        || "value",
                        self.t_range16,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
