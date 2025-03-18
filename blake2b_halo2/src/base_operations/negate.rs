use super::*;
use crate::auxiliar_functions::field_for;
use crate::base_operations::decompose_8::Decompose8Config;
use halo2_proofs::circuit::AssignedCell;

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
    // [Inigo comment - answered] If you only want to negate, why are you assigning the decomposition of the value?
    //
    // Not operation is used only once in the last block of input. So we think it's better to
    // leave this function using the decomposition for simplicity, since it won't change the circuit
    // performance. Is just to keep the uniformity in the way we represent operations in the trace.
    pub fn generate_rows_from_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &AssignedCell<F, F>,
        decompose_config: &mut Decompose8Config,
    ) -> Result<AssignedCell<F, F>, Error> {
        // [Inigo comment - solved] You are unlinking the cell with the actual value - this might be a
        // soundness issue.
        //
        // Solution - We changed generate_row_from_value for generate_row_from_cell which adds a
        // copy constraint between input and the new cell
        self.q_negate.enable(region, *offset)?;
        let result_value = input.value().map(|v0| F::from(((1u128 << 64) - 1) as u64) - *v0);
        decompose_config.generate_row_from_cell(region, input, *offset)?;
        *offset += 1;
        let result_cell =
            decompose_config.generate_row_from_value(region, result_value, *offset)?;
        *offset += 1;
        Ok(result_cell)
    }
}
