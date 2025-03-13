use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

/// This trait enables indistinct decomposition of a number into a set of limbs.
/// T is the amount of limbs that the number will be decomposed into.
pub trait Decomposition<const T: usize> {
    const LIMB_SIZE: usize;

    fn range_table_column(&self) -> TableColumn;

    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; T],
    ) -> Self;

    fn populate_row_from_values<F: PrimeField>(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
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

    fn generate_row_from_value<F: PrimeField>(
        &mut self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>;

    fn generate_row_from_bytes<F: PrimeField>(
        &mut self,
        _region: &mut Region<F>,
        _bytes: [Value<F>; 8],
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;

    fn generate_row_from_cell<F: PrimeField>(
        &mut self,
        region: &mut Region<F>,
        cell: &AssignedCell<F, F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = cell.value().copied();

        let new_cell = self.generate_row_from_value(region, value, offset)?;
        region.constrain_equal(cell.cell(), new_cell.cell())?;
        Ok(vec![new_cell])
    }

    fn generate_row_from_value_and_keep_row<F: PrimeField>(
        &mut self,
        _region: &mut Region<F>,
        _value: Value<F>,
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error>;

    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F>;
}
