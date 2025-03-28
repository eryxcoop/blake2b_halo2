use super::*;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::types::{AssignedBit, AssignedBlake2bWord, Blake2bWord};
use auxiliar_functions::field_for;

#[derive(Clone, Debug)]
// [zhiyong comment - answered] How about include decompoisition_config here and use decoposition_config.configure(), other than
// remembering always this is implicit
//
// We can make the AdditionMod64Config hold the decomposition chip, but the decomposition chip instance must be the same for all
// the blake2b_chip operations because the selectors we're turning on must be in the same columns, to avoid duplicating columns in the circuit
pub struct AdditionMod64Config {
    carry: Column<Advice>,
    pub q_add: Selector,
    pub decomposition: Decompose8Config,
}

impl AdditionMod64Config {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        carry: Column<Advice>,
        decomposition: Decompose8Config
    ) -> Self {
        let q_add = meta.complex_selector();

        /// The gate that will be used to check the sum of two numbers mod 2^64
        /// The gate is defined as:
        ///     sum mod 2 ^ 64 = full_number_result - full_number_x - full_number_y
        ///                     + carry * (1 << 64)
        ///    carry = carry * (1 << 0) - carry
        ///
        /// Note that the full number is implicitly range checked to be a 64-bit number because we
        /// are using 8-bit limbs (we are using the decompose 8 config)
        meta.create_gate("sum mod 2 ^ 64", |meta| {
            let q_add = meta.query_selector(q_add);
            let full_number_x = meta.query_advice(full_number_u64, Rotation(0));
            let full_number_y = meta.query_advice(full_number_u64, Rotation(1));
            let full_number_result = meta.query_advice(full_number_u64, Rotation(2));
            let carry = meta.query_advice(carry, Rotation(1));

            vec![
                q_add.clone()
                    * (full_number_result - full_number_x - full_number_y
                        + carry.clone() * (Expression::Constant(field_for(1u128 << 64)))),
                q_add * carry.clone() * (Expression::Constant(field_for(1u128)) - carry),
            ]
        });

        Self { carry, q_add, decomposition }
    }

    /// This method receives two cells, and generates the rows for the addition of their values.
    /// We copy the values of the cells to the trace, and then calculate the result and carry
    /// of the addition and write it in a third row.
    ///
    /// When one of the addition parameters (previous_cell)
    /// is the last cell that was generated in the circuit, by setting the use_last_cell_as_first_operand
    /// to true we can avoid generating the row for the previous_cell again, and just copy the cell_to_copy.
    pub fn generate_addition_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        use_last_cell_as_first_operand: bool,
        full_number_u64_column: Column<Advice>,
    ) -> Result<(AssignedBlake2bWord<F>, AssignedBit<F>), Error> {
        let (result_value, carry_value) =
            Self::calculate_result_and_carry(previous_cell.value(), cell_to_copy.value());
        let offset_to_enable = *offset - if use_last_cell_as_first_operand { 1 } else { 0 };
        self.q_add.enable(region, offset_to_enable)?;

        if !use_last_cell_as_first_operand {
            previous_cell.0.copy_advice(
                || "Sum first operand",
                region,
                full_number_u64_column,
                *offset
            )?;
            *offset += 1;
        }
        cell_to_copy.0.copy_advice(
           || "Sum second operand",
           region,
           full_number_u64_column,
           *offset
        )?;
        let carry_cell = AssignedBit::assign_advice_bit(region,"carry", self.carry, *offset, carry_value)?;
        *offset += 1;

        let result_cell = self.decomposition.generate_row_from_value(region, result_value, *offset)?;
        *offset += 1;

        Ok((result_cell, carry_cell))
    }

    fn calculate_result_and_carry<F: PrimeField>(
        lhs: Value<Blake2bWord>,
        rhs: Value<Blake2bWord>,
    ) -> (Value<Blake2bWord>, Value<F>) {
        let result_value = lhs.and_then(|l| rhs.and_then(|r| {
            Value::known(auxiliar_functions::sum_mod_64(l, r))
        }));
        let carry_value = lhs.and_then(|l| rhs.and_then(|r| {
            Value::known(auxiliar_functions::carry_mod_64(l, r))
        }));
        (result_value, carry_value)
    }
}
