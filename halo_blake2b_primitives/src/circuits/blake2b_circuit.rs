use super::*;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use std::array;

pub struct Blake2bCircuit<F: Field, const BLOCKS: usize> {
    _ph: PhantomData<F>,
    output_size: Value<F>,
    input: [[Value<F>; 16]; BLOCKS],
    input_size: Value<F>,
}

#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
}

impl<F: PrimeField, const BLOCKS: usize> Circuit<F> for Blake2bCircuit<F, BLOCKS> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            output_size: Value::unknown(),
            input: [[Value::unknown(); 16]; BLOCKS],
            input_size: Value::unknown(),
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

        let carry = meta.advice_column();

        let blake2b_table16_chip =
            Blake2bTable16Chip::configure(meta, full_number_u64, limbs, carry);

        Self::Config {
            _ph: PhantomData,
            blake2b_table16_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.blake2b_table16_chip.initialize_with(&mut layouter);
        config.blake2b_table16_chip.compute_blake2b_hash_for_inputs(
            &mut layouter,
            self.output_size,
            self.input_size,
            self.input,
        )
    }
}

impl<F: PrimeField, const BLOCKS: usize> Blake2bCircuit<F, BLOCKS> {
    pub fn new_for(
        output_size: Value<F>,
        input: [[Value<F>; 16]; BLOCKS],
        input_size: Value<F>,
    ) -> Self {
        Self {
            _ph: PhantomData,
            output_size,
            input,
            input_size,
        }
    }
}
