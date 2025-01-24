use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use std::array;
use halo2_proofs::circuit::{AssignedCell, Cell};
use halo2_proofs::plonk::Fixed;
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;

pub struct ManyOperationsCircuit<F: PrimeField> {
    _ph: PhantomData<F>,
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
    expected_result: Value<F>,
}

#[derive(Clone)]
pub struct ManyOperationsCircuitConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_chip: Blake2bTable16Chip<F>,
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
    type Config = ManyOperationsCircuitConfig<F>;
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

        let blake2b_chip = Blake2bTable16Chip::configure(
            decompose_8_chip,
            addition_chip,
            generic_limb_rotation_chip,
            rotate_63_chip,
            xor_chip
        );

        Self::Config {
            _ph: PhantomData,
            blake2b_chip,
            fixed,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        // initialize
        config.blake2b_chip.initialize_with(&mut layouter);

        let addition_result = config.blake2b_chip.add(self.a, self.b, &mut layouter);
        let xor_result = config.blake2b_chip.xor(addition_result, self.c, &mut layouter);
        let rotate63_result = config.blake2b_chip.rotate_right_63(xor_result, &mut layouter);
        let rotate16_result = config.blake2b_chip.rotate_right_16(rotate63_result, &mut layouter);
        let rotate24_result = config.blake2b_chip.rotate_right_24(rotate16_result, &mut layouter);
        let rotate32_result = config.blake2b_chip.rotate_right_32(rotate24_result, &mut layouter);

        // Check the result equals the expected one
        rotate32_result.and_then(|x| self.expected_result.and_then(|y| {
            assert_eq!(x, y);
            Value::<F>::unknown()
        }));

        Ok(())
    }
}
