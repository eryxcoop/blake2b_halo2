use super::*;

#[derive(Clone, Debug)]
pub struct Rotate24Chip<F: Field> {
    q_rot24: Selector,
    // full_number_u64: Column<Advice>,
    // limbs: [Column<Advice>; 4],
    // decompose_8_chip: Decompose8Chip<F>,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Rotate24Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 4],
        decompose_8_chip: Decompose8Chip<F>,
    ) -> Self {
        let q_rot24 = meta.complex_selector();
        // 0 = (x*2^40 + z) - z*2^64 - y
        meta.create_gate("rotate right 24", |meta| {
            let q_rot24 = meta.query_selector(q_rot24);
            let input_full_number = meta.query_advice(full_number_u64, Rotation(0));
            let chunk = meta.query_advice(full_number_u64, Rotation(1));
            let output_full_number = meta.query_advice(full_number_u64, Rotation(2));
            vec![
                q_rot24
                    * (Expression::Constant(F::from((1u128 << 40) as u64))
                        * input_full_number.clone()
                        + chunk.clone()
                        - Expression::Constant(F::from((1u128 << 63) as u64) * F::from(2))
                            * chunk.clone()
                        - output_full_number.clone()),
            ]
        });

        meta.lookup("lookup rotate_24 chunks", |meta| {
            let limb: Expression<F> = meta.query_advice(limbs[2], Rotation(1));
            let q_rot24 = meta.query_selector(q_rot24);
            vec![(q_rot24 * limb, decompose_8_chip.t_range8)]
        });

        Self {
            q_rot24,
            _ph: PhantomData,
        }
    }
    pub fn assign_rotation_rows(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_chip: &mut Decompose16Chip<F>,
        trace: [[Value<F>; 5]; 3],
    ) {
        let _ = layouter.assign_region(
            || "rotate 24",
            |mut region| {
                let _ = self.q_rot24.enable(&mut region, 0);

                let first_row = trace[0].to_vec();
                let second_row = trace[1].to_vec();
                let third_row = trace[2].to_vec();
                decompose_chip.assign_16bit_row_from_values(&mut region, first_row.clone(), 0);
                decompose_chip.assign_16bit_row_from_values(&mut region, second_row.clone(), 1);
                decompose_chip.assign_16bit_row_from_values(&mut region, third_row.clone(), 2);

                Ok(())
            },
        );
    }
}
