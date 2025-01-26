use super::*;
use halo2_proofs::circuit::AssignedCell;
use crate::auxiliar_functions::{field_for};
use crate::chips::decompose_8_chip::Decompose8Chip;

#[derive(Clone, Debug)]
pub struct NegateChip<F: Field> {
    q_negate: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> NegateChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
    ) -> Self {
        let q_negate = meta.complex_selector();

        meta.create_gate("negate", |meta| {
            let q_negate = meta.query_selector(q_negate);
            let value = meta.query_advice(full_number_u64, Rotation(0));
            let not_value = meta.query_advice(full_number_u64, Rotation(1));

            vec![
                q_negate
                    * (Expression::Constant(field_for((1u128 << 64) - 1)) - value - not_value),
            ]
        });

        Self {
            q_negate,
            _ph: PhantomData,
        }
    }

    pub fn generate_rows(
        &mut self,
        layouter: &mut impl Layouter<F>,
        value: Value<F>,
        decompose_chip: &mut Decompose8Chip<F>
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "sum",
            |mut region| {
                let _ = self.q_negate.enable(&mut region, 0);
                let result_value = value.and_then(|v0| {
                    Value::known(F::from(((1u128 << 64) - 1) as u64) - v0)
                });
                decompose_chip.generate_row_from_value(&mut region, value, 0)?;
                let result_cell = decompose_chip.generate_row_from_value(&mut region, result_value, 1)?;
                Ok(result_cell)
            },
        )
    }
}
