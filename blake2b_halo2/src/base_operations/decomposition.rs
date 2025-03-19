use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

/// This trait enables indistinct decomposition of a number into a set of limbs, where each limbs is range checked regarding the
/// designated limb size.
/// T is the amount of limbs that the number will be decomposed into.
/// Little endian representation is used for the limbs.
/// We also expect F::Repr to be little endian in all usages of this trait.
pub trait Decomposition<const T: usize> {
    const LIMB_SIZE: usize;

    fn range_table_column(&self) -> TableColumn;

    /// Given an explicit vector of values, it assigns the full number and the limbs in a row of the trace
    /// row size is T + 1
    /// row[0] is the full number
    /// row[1..T] are the limbs representation of row[0]
    fn populate_row_from_values<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row: &[Value<F>],
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;

    /// Populates the table for the range check
    fn populate_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || format!("range {}-bit check table", Self::LIMB_SIZE),
            |mut table| {
                for i in 0..1 << Self::LIMB_SIZE {
                    table.assign_cell(
                        || "value",
                        self.range_table_column(),
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    fn range_check_for_limb<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_decompose: &Selector,
        t_range: &TableColumn,
    ) {
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_decompose = meta.query_selector(*q_decompose);
            vec![(q_decompose * limb, *t_range)]
        });
    }

    /// Given a value of 64 bits, it generates a row with the assigned cells for the full number
    /// and the limbs, and returns the full number
    fn generate_row_from_value<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>;

    /// Given a cell with a 64-bit value, it returns a new row with the copied full number and the
    /// decomposition in 8-bit limbs
    fn generate_row_from_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        cell: &AssignedCell<F, F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = cell.value().copied();
        let new_cells = self.generate_row_from_value_and_keep_row(region, value, offset)?;
        // [Inigo comment - solved] This seems very dangerous, and food for bugs. `generate_row_from_value_and_keep_row`
        // should be properly document (I think I made this comment somewhere else in the code base)
        //
        // Added docs in `generate_row_from_value_and_keep_row` to specify the result row structure
        region.constrain_equal(cell.cell(), new_cells[0].cell())?;
        Ok(new_cells)
    }

    /// Convenience method for generating a row from a value and keeping the full row.
    /// Given a Value, we might want to use it as an operand in the circuit, and sometimes we need
    /// to establish constraints over the result's limbs. That's why we need a way to retrieve the
    /// full row that was created from that value. An example of this could be the Generic Limb
    /// Rotation Operation, where we need to establish copy constraints over the rotated limbs.
    /// The result row size is T + 1
    /// row[0] is the full number
    /// row[1..T] are the limbs representation of row[0]
    fn generate_row_from_value_and_keep_row<F: PrimeField>(
        &self,
        _region: &mut Region<F>,
        _value: Value<F>,
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;

    /// Given a value and a limb index, it returns the value of the limb
    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F>;

    fn get_full_number_u64_column(&self) -> Column<Advice>;
}
