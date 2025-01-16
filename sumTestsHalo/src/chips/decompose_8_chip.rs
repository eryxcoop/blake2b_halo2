use super::*;

#[derive(Clone, Debug)]
struct Decompose8Chip<F: Field> {
    full_number_u64: Column<Advice>,
    limbs_8_bits: [Column<Advice>; 8],
    q_decompose_8: Selector,
    t_range_8: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Decompose8Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs_8_bits: [Column<Advice>; 8],
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

        let t_range8 = meta.lookup_table_column();
        for limb in limbs_8_bits {
            meta.lookup("lookup range check 8 bits", |meta| {
                let limb: Expression<F> = meta.query_advice(limb, Rotation::cur());
                let q_decompose_8 = meta.query_selector(q_decompose_8);
                vec![(q_decompose_8 * limb, t_range8)]
            });
        }

        Decompose8Chip {}
    }
}
