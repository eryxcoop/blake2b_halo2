use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn};

pub trait Decomposition<F: PrimeField, const T: usize> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; T],
    ) -> Self;

    fn populate_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) -> Option<Vec<AssignedCell<F, F>>>;

    fn populate_lookup_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

    fn _populate_lookup_table(
        layouter: &mut impl Layouter<F>,
        lookup_column: TableColumn,
    ) -> Result<(), Error>;

    fn _range_check_for_limb(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_decompose: &Selector,
        t_range: &TableColumn,
    );

    fn generate_row_from_value(
        &mut self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>;

    fn generate_row_from_cell(
        &mut self,
        _region: &mut Region<F>,
        _cell: AssignedCell<F, F>,
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        panic!("Not implemented");
    }

    fn generate_row_from_value_and_keep_row(
        &mut self,
        _region: &mut Region<F>,
        _value: Value<F>,
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        panic!("Not implemented");
    }
}
