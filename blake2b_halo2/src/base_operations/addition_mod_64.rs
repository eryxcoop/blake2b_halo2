use super::*;
use crate::types::AssignedNative;
use auxiliar_functions::field_for;

pub type AdditionConfigWith8Limbs = AdditionMod64Config<8, 10>;

#[derive(Clone, Debug)]
/// This config uses two generics, T and R.
/// T is used to define the number of limbs we will use to represent numbers in the trace
/// (it will be 4 for 16b limbs or 8 for 8b limbs)
///
/// R is used to define the total number of columns in the trace.
/// It will allways be T + 2 (full number and carry)
pub struct AdditionMod64Config<const T: usize, const R: usize> {
    pub carry: Column<Advice>,
    pub q_add: Selector,
}

impl<const T: usize, const R: usize> AdditionMod64Config<T, R> {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        carry: Column<Advice>,
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
            let carry = meta.query_advice(carry, Rotation(2));

            vec![
                q_add.clone()
                    * (full_number_result - full_number_x - full_number_y
                        + carry.clone() * (Expression::Constant(field_for(1u128 << 64)))),
                q_add * carry.clone() * (Expression::Constant(field_for(1u128)) - carry),
            ]
        });

        Self { carry, q_add }
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
        previous_cell: &AssignedNative<F>,
        cell_to_copy: &AssignedNative<F>,
        decompose_config: &impl Decomposition<T>,
        use_last_cell_as_first_operand: bool,
    ) -> Result<[AssignedNative<F>; 2], Error> {
        let (result_value, carry_value) =
            Self::calculate_result_and_carry(previous_cell.value(), cell_to_copy.value());
        let offset_to_enable = *offset - if use_last_cell_as_first_operand { 1 } else { 0 };
        self.q_add.enable(region, offset_to_enable)?;

        if !use_last_cell_as_first_operand {
            decompose_config.generate_row_from_cell(region, previous_cell, *offset)?;
            *offset += 1;
        }
        // decompose_config.generate_row_from_cell(region, cell_to_copy, *offset)?;
        cell_to_copy.copy_advice(
           || "Sum first operand",
           region,
           decompose_config.get_full_number_u64_column(),
           *offset
        )?;
        *offset += 1;

        let result_cell =
            decompose_config.generate_row_from_value(region, result_value, *offset)?;
        let carry_cell = region.assign_advice(|| "carry", self.carry, *offset, || carry_value)?;
        *offset += 1;
        Ok([result_cell, carry_cell])
    }

    fn calculate_result_and_carry<F: PrimeField>(
        lhs: Value<&F>,
        rhs: Value<&F>,
    ) -> (Value<F>, Value<F>) {
        let [result_value, carry_value] = lhs
            .zip(rhs)
            .map(|(a, b)| {
                [auxiliar_functions::sum_mod_64(*a, *b), auxiliar_functions::carry_mod_64(*a, *b)]
            })
            .transpose_array();

        (result_value, carry_value)
    }
}
