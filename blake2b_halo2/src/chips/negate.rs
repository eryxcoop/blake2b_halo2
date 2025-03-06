use super::*;
use crate::auxiliar_functions::field_for;
use crate::chips::decompose_8::Decompose8Config;
use halo2_proofs::circuit::AssignedCell;

/// This config handles the bitwise negation of a 64-bit number.
#[derive(Clone, Debug)]
pub struct NegateConfig<F: Field> {
    q_negate: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> NegateConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, full_number_u64: Column<Advice>) -> Self {
        let q_negate = meta.complex_selector();

        /// The gate that will be used to negate a number
        /// The gate is defined as:
        ///    negate = (1 << 64) - value - not_value
        meta.create_gate("negate", |meta| {
            let q_negate = meta.query_selector(q_negate);
            let value = meta.query_advice(full_number_u64, Rotation(0));
            let not_value = meta.query_advice(full_number_u64, Rotation(1));

            vec![
                q_negate * (Expression::Constant(field_for((1u128 << 64) - 1)) - value - not_value),
            ]
        });

        Self {
            q_negate,
            _ph: PhantomData,
        }
    }

    pub fn generate_rows_from_cell(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &AssignedCell<F, F>,
        decompose_config: &mut Decompose8Config<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let value = input.value().copied();
        self.generate_rows(region, offset, value, decompose_config)
    }

    /// Receives a value, generates a row for that value and generates the row for the negation
    /// of the value
    pub fn generate_rows(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        value: Value<F>,
        decompose_config: &mut Decompose8Config<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.q_negate.enable(region, *offset)?;
        let result_value =
            value.and_then(|v0| Value::known(F::from(((1u128 << 64) - 1) as u64) - v0));
        decompose_config.generate_row_from_value(region, value, *offset)?;
        *offset += 1;
        let result_cell = decompose_config.generate_row_from_value(region, result_value, *offset)?;
        *offset += 1;
        Ok(result_cell)
    }
}
