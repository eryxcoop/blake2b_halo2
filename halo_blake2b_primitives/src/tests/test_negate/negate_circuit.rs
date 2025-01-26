use super::*;
use std::array;
use std::marker::PhantomData;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed};
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::negate_chip::NegateChip;

pub struct NegateCircuit<F: PrimeField> {
    _ph: PhantomData<F>,
    value: Value<F>,
    expected_result: Value<F>,
}

#[derive(Clone)]
pub struct NegateCircuitConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    negate_chip: NegateChip<F>,
    decompose_8_chip: Decompose8Chip<F>,
    fixed_result: Column<Fixed>,
}

impl<F: PrimeField> Circuit<F> for NegateCircuit<F> {
    type Config = NegateCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            value: Value::unknown(),
            expected_result: Value::unknown(),
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);

        let negate_chip = NegateChip::<F>::configure(meta, full_number_u64);

        let fixed_result = meta.fixed_column();
        meta.enable_equality(full_number_u64);
        meta.enable_equality(fixed_result);

        Self::Config {
            _ph: PhantomData,
            negate_chip,
            decompose_8_chip,
            fixed_result,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .decompose_8_chip
            .populate_lookup_table(&mut layouter)?;
        let result = config.negate_chip.generate_rows(
            &mut layouter,
            self.value,
            &mut config.decompose_8_chip,
        )?;

        Self::assert_cell_value(
            &mut layouter,
            &result,
            config.fixed_result,
            self.expected_result,
        )?;
        Ok(())
    }

}

impl<F: PrimeField> NegateCircuit<F> {
    fn assert_cell_value(
        layouter: &mut impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        fixed_column: Column<Fixed>,
        expected_value: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed",
            |mut region| {
                // add the value to the fixed column
                // if the same constant is used multiple times,
                // we could optimize this by caching the cell
                let fixed_cell =
                    region.assign_fixed(|| "assign fixed", fixed_column, 0, || expected_value)?;
                region.constrain_equal(cell.cell(), fixed_cell.cell())?;
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn new_for(
        value: Value<F>,
        expected_result: Value<F>,
    ) -> Self {
        Self {
            _ph: PhantomData,
            value,
            expected_result,
        }
    }
}
