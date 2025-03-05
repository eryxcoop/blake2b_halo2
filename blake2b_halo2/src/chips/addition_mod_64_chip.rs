use super::*;
use auxiliar_functions::field_for;
use halo2_proofs::circuit::AssignedCell;

pub type AdditionChipWith8Limbs<F> = AdditionMod64Chip<F, 8, 10>;
pub type AdditionChipWith4Limbs<F> = AdditionMod64Chip<F, 4, 6>;

#[derive(Clone, Debug)]
// Rather than the 'Chip' we refer to this as the 'Configuration', as you are only specifying
// columns. See here https://github.com/midnightntwrk/midnight-circuits/blob/main/src/hash/sha256/table11/range16.rs#L27
// Then the chip contains the config (possibly different configs, or even other chips).
/// This config uses two generics, T and R.
/// T is used to define the number of limbs we will use to represent numbers in the trace
/// (it will be 4 for 16b limbs or 8 for 8b limbs)
///
/// R is used to define the total number of columns in the trace.
/// It will allways be T + 2 (full number and carry)
pub struct AdditionMod64Chip<F: Field, const T: usize, const R: usize> {
    carry: Column<Advice>,
    q_add: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField, const T: usize, const R: usize> AdditionMod64Chip<F, T, R> {
    pub fn configure(
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

        Self {
            carry,
            q_add,
            _ph: PhantomData,
        }
    }

    /// This method is meant to receive a valid addition_trace, and populate the circuit with it
    /// The addition trace is a matrix with 3 rows and R columns. The rows represent the two
    /// parameters of the addition and its result.
    /// Each row has the following format:
    ///    [full_number, limb_0, ..., limb_R-2, carry]
    /// Note that the carry value is not used in the parameters of the addition, but it is used
    /// to calculate its result.
    pub fn populate_addition_rows(
        &mut self,
        layouter: &mut impl Layouter<F>,
        addition_trace: [[Value<F>; R]; 3],
        decompose_chip: &mut impl Decomposition<F, T>,
    ) -> Result<(), Error>{

        layouter.assign_region(
            || "decompose",
            |mut region| {
                self.q_add.enable(&mut region, 0)?;

                self.populate_row_from_values(
                    &mut region,
                    addition_trace[0].to_vec(),
                    0,
                    decompose_chip,
                )?;
                self.populate_row_from_values(
                    &mut region,
                    addition_trace[1].to_vec(),
                    1,
                    decompose_chip,
                )?;
                self.populate_row_from_values(
                    &mut region,
                    addition_trace[2].to_vec(),
                    2,
                    decompose_chip,
                )
            },
        )?;
        Ok(())
    }

    /// This method receives two cells, and generates the rows for the addition of their values.
    /// We copy the values of the cells to the trace, and then calculate the result and carry
    /// of the addition and write it in a third row.
    pub fn generate_addition_rows_from_cells(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        cell_a: &AssignedCell<F, F>,
        cell_b: &AssignedCell<F, F>,
        decompose_chip: &mut impl Decomposition<F, T>,
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        let (result_value, carry_value) = Self::calculate_result_and_carry(cell_a.value(), cell_b.value());

        self.q_add.enable(region, *offset)?;
        decompose_chip.generate_row_from_cell(region, cell_a, *offset)?;
        *offset += 1;
        decompose_chip.generate_row_from_cell(region, cell_b, *offset)?;
        *offset += 1;
        let result_cell = decompose_chip.generate_row_from_value(region, result_value, *offset)?;
        let carry_cell = region.assign_advice(|| "carry", self.carry, *offset, || carry_value)?;
        *offset += 1;
        Ok([result_cell, carry_cell])
    }

    /// This method is intended to be used when one of the addition parameters (previous_cell)
    /// is the last cell that was generated in the circuit. This way, we can avoid generating
    /// the row for the previous_cell again, and just copy the cell_to_copy.
    pub fn generate_addition_rows_from_cells_optimized(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        decompose_chip: &mut impl Decomposition<F, T>,
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        let (result_value, carry_value) =
            Self::calculate_result_and_carry(previous_cell.value(), cell_to_copy.value());

        self.q_add.enable(region, *offset - 1)?;
        decompose_chip.generate_row_from_cell(region, cell_to_copy, *offset)?;
        *offset += 1;
        let result_cell = decompose_chip.generate_row_from_value(region, result_value, *offset)?;
        let carry_cell = region.assign_advice(|| "carry", self.carry, *offset, || carry_value)?;
        *offset += 1;
        Ok([result_cell, carry_cell])
    }

    fn calculate_result_and_carry(
        lhs: Value<&F>,
        rhs: Value<&F>,
    ) -> (Value<F>, Value<F>) {
        let [result_value, carry_value] = lhs.zip(rhs).map(|(a, b)| {
            [
                auxiliar_functions::sum_mod_64(*a, *b),
                auxiliar_functions::carry_mod_64(*a, *b)
            ]
        }).transpose_array();

        (result_value, carry_value)
    }

    fn populate_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
        decompose_chip: &mut impl Decomposition<F, T>,
    ) -> Result<(), Error> {
        decompose_chip.populate_row_from_values(region, row.clone(), offset)?;
        region.assign_advice(|| "carry", self.carry, offset, || row[R - 1])?;
        Ok(())
    }
}
