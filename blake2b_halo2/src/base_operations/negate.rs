use super::*;
use crate::auxiliar_functions::{field_for, value_for};
use crate::types::{AssignedBlake2bWord, AssignedElement, AssignedNative, Blake2bWord};

/// This config handles the bitwise negation of a 64-bit number.
#[derive(Clone, Debug)]
pub struct NegateConfig {
    q_negate: Selector,
}

impl NegateConfig {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
    ) -> Self {
        let q_negate = meta.complex_selector();

        /// The gate that will be used to negate a number
        /// The gate is defined as:
        ///    negate = (1 << 64) - 1 - value - not_value
        meta.create_gate("negate", |meta| {
            let q_negate = meta.query_selector(q_negate);
            let value = meta.query_advice(full_number_u64, Rotation(0));
            let not_value = meta.query_advice(full_number_u64, Rotation(1));

            vec![
                q_negate * (Expression::Constant(field_for((1u128 << 64) - 1)) - value - not_value),
            ]
        });

        Self { q_negate }
    }

    /// Receives a cell, generates a new row for that cell and generates the row for the negation
    /// of the value
    pub fn generate_rows_from_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &AssignedBlake2bWord<F>,
        full_number_column: Column<Advice>,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.q_negate.enable(region, *offset)?;
        input.0.copy_advice(|| "Negation input", region, full_number_column, *offset)?;
        *offset += 1;

        let result_value: Value<Blake2bWord> = input.value().map(|input| Blake2bWord(((1u128 << 64) - 1) as u64 - input.0));

        let result_cell: AssignedNative<F> = region.assign_advice(
            || "Negation output",
            full_number_column,
            *offset,
            || result_value.and_then(|v|value_for(v.0)),
        )?;
        *offset += 1;
        Ok(AssignedBlake2bWord(result_cell))
    }
}
