use super::*;

#[derive(Clone, Debug)]
pub struct SumMod64Chip<F: Field> {
    decompose_16_chip: Decompose16Chip<F>,
    full_number_u64: Column<Advice>,
    carry: Column<Advice>,
    limbs: [Column<Advice>; 4],
    pub q_add: Selector,
    t_range16: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> SumMod64Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        limbs: [Column<Advice>; 4],
        decompose_16_chip: Decompose16Chip<F>,
        full_number_u64: Column<Advice>,
        carry: Column<Advice>,
        t_range16: TableColumn,
    ) -> Self {
        let q_add = meta.complex_selector();

        meta.create_gate("sum mod 2 ^ 64", |meta| {
            let q_add = meta.query_selector(q_add);
            let full_number_x = meta.query_advice(full_number_u64, Rotation(0));
            let full_number_y = meta.query_advice(full_number_u64, Rotation(1));
            let full_number_result = meta.query_advice(full_number_u64, Rotation(2));

            let carry = meta.query_advice(carry, Rotation(2));
            // TODO check if x, y and result are 64 bits
            vec![
                q_add
                    * (full_number_result - full_number_x - full_number_y
                        + carry
                            * (Expression::Constant(F::from(((1u128 << 64) - 1) as u64))
                                + Expression::Constant(F::ONE))),
            ]
        });

        for limb in limbs {
            Self::range_check_for_limb_16_bits(
                meta,
                &limb,
                &decompose_16_chip.q_decompose,
                &t_range16,
            );
        }

        Self {
            decompose_16_chip,
            full_number_u64,
            limbs,
            carry,
            q_add,
            t_range16,
            _ph: PhantomData,
        }
    }

    fn range_check_for_limb_16_bits(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_decompose: &Selector,
        t_range16: &TableColumn,
    ) {
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_decompose = meta.query_selector(*q_decompose);
            vec![(q_decompose * limb, *t_range16)]
        });
    }

    pub fn assign_addition_rows(
        &mut self,
        layouter: &mut impl Layouter<F>,
        addition_trace: [[Value<F>; 6]; 3],
    ) {
        let _ = layouter.assign_region(
            || "decompose",
            |mut region| {
                let _ = self.q_add.enable(&mut region, 0);

                Self::assign_row_from_values(self, &mut region, addition_trace[0].to_vec(), 0);
                Self::assign_row_from_values(self, &mut region, addition_trace[1].to_vec(), 1);
                Self::assign_row_from_values(self, &mut region, addition_trace[2].to_vec(), 2);
                Ok(())
            },
        );
    }

    fn assign_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) {
        let _ = self
            .decompose_16_chip
            .assign_16bit_row_from_values(region, row.clone(), offset);

        let _ = region.assign_advice(|| "carry", self.carry, offset, || row[5]);
    }
}
