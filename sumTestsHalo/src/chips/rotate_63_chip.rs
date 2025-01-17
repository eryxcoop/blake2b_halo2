use super::*;

#[derive(Clone, Debug)]
pub struct Rotate63Chip<F: Field> {
    pub q_rot63: Selector,
    full_number_u64: Column<Advice>,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Rotate63Chip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, full_number_u64: Column<Advice>) -> Self{
        let q_rot63 = meta.complex_selector();
        meta.create_gate("rotate right 63", |meta| {
            let q_rot63 = meta.query_selector(q_rot63);
            let input_full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let output_full_number = meta.query_advice(full_number_u64, Rotation::next());
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
            q_rot63,
            full_number_u64,
            _ph: PhantomData,
        }
    }
}