use super::*;
use crate::chips::blake2b_chip_sum_with_4_limbs::Blake2bChip_SumWith4Limbs;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;

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
    blake2b_chip: Blake2bChip_SumWith4Limbs<F>,
}

impl<F: PrimeField> ManyOperationsCircuit<F> {
    pub fn new_for(a: Value<F>, b: Value<F>, c: Value<F>, expected_result: Value<F>) -> Self {
        Self {
            _ph: PhantomData,
            a,
            b,
            c,
            expected_result,
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

        let blake2b_chip = Blake2bChip_SumWith4Limbs::configure(meta, full_number_u64, limbs);

        Self::Config {
            _ph: PhantomData,
            blake2b_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // initialize
        // TODO ver que hacemos con esto
        config.blake2b_chip.initialize_with(&mut layouter);

        let a = config.blake2b_chip.new_row_from_value(self.a, &mut layouter)?;
        let b = config.blake2b_chip.new_row_from_value(self.b, &mut layouter)?;
        let c = config.blake2b_chip.new_row_from_value(self.c, &mut layouter)?;

        let addition_result = config.blake2b_chip.add(a, b, &mut layouter);
        let xor_result = config.blake2b_chip.xor(addition_result, c, &mut layouter);
        let rotate63_result = config.blake2b_chip.rotate_right_63(xor_result, &mut layouter);
        let rotate16_result = config.blake2b_chip.rotate_right_16(rotate63_result, &mut layouter);
        let rotate24_result = config.blake2b_chip.rotate_right_24(rotate16_result, &mut layouter);
        let rotate32_result = config.blake2b_chip.rotate_right_32(rotate24_result, &mut layouter);

        rotate32_result.value().cloned().and_then(|x| {
            self.expected_result.and_then(|y| {
                assert_eq!(x, y);
                Value::<F>::unknown()
            })
        });

        Ok(())
    }
}
