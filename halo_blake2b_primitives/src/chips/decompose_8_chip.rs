use super::*;

#[derive(Clone, Debug)]
pub struct Decompose8Chip<F: Field> {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
    q_decompose: Selector,
    pub t_range8: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Decompose8Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs_8_bits: [Column<Advice>; 8],
        t_range8: TableColumn,
    ) -> Self {
        let q_decompose_8 = meta.complex_selector();
        meta.create_gate("decompose in 8 bit words", |meta| {
            let q_decompose_8 = meta.query_selector(q_decompose_8);
            let full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let limbs: Vec<Expression<F>> = limbs_8_bits
                .iter()
                .map(|column| meta.query_advice(*column, Rotation::cur()))
                .collect();
            vec![
                q_decompose_8
                    * (full_number
                        - limbs[0].clone()
                        - limbs[1].clone() * Expression::Constant(F::from(1 << 8))
                        - limbs[2].clone() * Expression::Constant(F::from(1 << 16))
                        - limbs[3].clone() * Expression::Constant(F::from(1 << 24))
                        - limbs[4].clone() * Expression::Constant(F::from(1 << 32))
                        - limbs[5].clone() * Expression::Constant(F::from(1 << 40))
                        - limbs[6].clone() * Expression::Constant(F::from(1 << 48))
                        - limbs[7].clone() * Expression::Constant(F::from(1 << 56))),
            ]
        });

        for limb in limbs_8_bits {
            Self::_range_check_for_limb_8_bits(meta, &limb, &q_decompose_8, &t_range8);
        }

        Self {
            full_number_u64,
            limbs: limbs_8_bits,
            q_decompose: q_decompose_8,
            t_range8,
            _ph: PhantomData,
        }
    }

    fn _range_check_for_limb_8_bits(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_decompose_8: &Selector,
        t_range8: &TableColumn,
    ) {
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_decompose_8 = meta.query_selector(*q_decompose_8);
            vec![(q_decompose_8 * limb, *t_range8)]
        });
    }

    pub fn range_check_for_limb_8_bits(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
    ) {
        Self::_range_check_for_limb_8_bits(meta, limb, &self.q_decompose, &self.t_range8);
    }

    pub fn assign_8bit_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) {
        let _ = self.q_decompose.enable(region, offset);
        let _ = region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0]);
        for i in 0..8 {
            let _ = region.assign_advice(
                || format!("limb{}", i),
                self.limbs[i],
                offset,
                || row[i + 1],
            );
        }
    }

    pub fn populate_lookup_table8(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let lookup_column = self.t_range8;
        Self::populate_lookup_table8_outside(layouter, lookup_column)
    }

    pub fn populate_lookup_table8_outside(
        layouter: &mut impl Layouter<F>,
        lookup_column: TableColumn,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "range 8bit check table",
            |mut table| {
                // assign the table
                for i in 0..1 << 8 {
                    table.assign_cell(
                        || "value",
                        lookup_column,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
