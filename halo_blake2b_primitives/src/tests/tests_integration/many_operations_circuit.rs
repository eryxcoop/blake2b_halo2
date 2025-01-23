use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use std::array;
use halo2_proofs::circuit::{AssignedCell, Cell};
use halo2_proofs::plonk::Fixed;
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;

pub struct ManyOperationsCircuit<F: Field> {
    _ph: PhantomData<F>,
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
    expected_result: Value<F>,
}

#[derive(Clone)]
pub struct XXXCircuitConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    addition_chip: AdditionMod64Chip<F, 8, 10>,
    decompose_8_chip: Decompose8Chip<F>,
    generic_limb_rotation_chip: LimbRotationChip<F>,
    rotate_63_chip: Rotate63Chip<F, 8, 9>,
    xor_chip: XorChip<F>,
    fixed: Column<Fixed>,
}


impl<F: PrimeField> ManyOperationsCircuit<F> {
    pub fn new_for(a: Value<F>, b: Value<F>, c: Value<F>, expected_result: Value<F>) -> Self {
        Self {
            _ph: PhantomData,
            a, b, c, expected_result
        }
    }
}

impl<F: PrimeField> Circuit<F> for ManyOperationsCircuit<F> {
    type Config = XXXCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            a: Value::unknown(),
            b: Value::unknown(),
            c: Value::unknown(),
            expected_result: Value::unknown(),
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        meta.enable_equality(full_number_u64);

        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        for limb in limbs {
            meta.enable_equality(limb);
        }

        let fixed = meta.fixed_column();
        meta.enable_equality(fixed);

        let carry = meta.advice_column();

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);
        let addition_chip = AdditionMod64Chip::<F, 8, 10>::configure(meta, full_number_u64, carry);
        let generic_limb_rotation_chip = LimbRotationChip::new();
        let rotate_63_chip = Rotate63Chip::configure(meta, full_number_u64);
        let xor_chip = XorChip::configure(meta, limbs);

        Self::Config {
            _ph: PhantomData,
            decompose_8_chip,
            addition_chip,
            generic_limb_rotation_chip,
            rotate_63_chip,
            xor_chip,
            fixed,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_chip.populate_lookup_table(&mut layouter)?;
        config.xor_chip.populate_xor_lookup_table(&mut layouter)?;

        let addition_result = config.addition_chip.generate_addition_rows(
            &mut layouter, self.a, self.b, &mut config.decompose_8_chip)?[0].clone();
        let xor_result = config.xor_chip.generate_xor_rows(
            &mut layouter, addition_result.value().copied(), self.c, &mut config.decompose_8_chip)?;
        let rotate63_result = config.rotate_63_chip.generate_rotation_rows(
            &mut layouter, xor_result.value().copied(), &mut config.decompose_8_chip)?;
        let rotate16_result = config.generic_limb_rotation_chip.generate_rotation_rows(
            &mut layouter, &mut config.decompose_8_chip, rotate63_result.value().copied(), 16)?;
        let rotate24_result = config.generic_limb_rotation_chip.generate_rotation_rows(
            &mut layouter, &mut config.decompose_8_chip, rotate16_result.value().copied(), 24)?;
        let rotate32_result = config.generic_limb_rotation_chip.generate_rotation_rows(
            &mut layouter, &mut config.decompose_8_chip, rotate24_result.value().copied(), 32)?;

        Self::assert_cell_value(&mut layouter, &rotate32_result, config.fixed, self.expected_result)?;

        Ok(())
    }
}


impl<F: PrimeField> ManyOperationsCircuit<F> {
    fn assert_cell_value(layouter: &mut impl Layouter<F>, cell: &AssignedCell<F, F>, fixed_column: Column<Fixed>, expected_value: Value<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed",
            |mut region| {
                // add the value to the fixed column
                // if the same constant is used multiple times,
                // we could optimize this by caching the cell
                let fixed_cell = region.assign_fixed(
                    || "assign fixed",
                    fixed_column,
                    0,
                    || {
                        expected_value
                    },
                )?;
                region.constrain_equal(cell.cell(), fixed_cell.cell())?;
                Ok(())
            },
        )?;
        Ok(())
    }
}
