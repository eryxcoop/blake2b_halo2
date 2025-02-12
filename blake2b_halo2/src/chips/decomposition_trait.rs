use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

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
    ){
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_decompose = meta.query_selector(*q_decompose);
            vec![(q_decompose * limb, *t_range)]
        });
    }

    fn generate_row_from_value(
        &mut self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>;

    fn generate_row_from_bytes(
        &mut self,
        _region: &mut Region<F>,
        _bytes: [Value<F>; 8],
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        panic!("Not implemented");
    }

    fn generate_row_from_cell(
        &mut self,
        region: &mut Region<F>,
        cell: AssignedCell<F, F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = cell.value().copied();

        let new_cell = self.generate_row_from_value(region, value, offset)?;
        region.constrain_equal(cell.cell(), new_cell.cell())?;
        Ok(vec![new_cell])
    }

    fn generate_row_from_value_and_keep_row(
        &mut self,
        _region: &mut Region<F>,
        _value: Value<F>,
        _offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        panic!("Not implemented");
    }

    fn get_limb_from(value: Value<F>, limb_number: usize) -> Value<F>;
}
