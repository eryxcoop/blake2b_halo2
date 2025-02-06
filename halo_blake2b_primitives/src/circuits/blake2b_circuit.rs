use super::*;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use crate::chips::blake2b_implementations::blake2b_chip::Blake2bChip;

pub struct Blake2bCircuit<F: Field, const BLOCKS: usize, const OUT_LEN: usize> {
    _ph: PhantomData<F>,
    input: [[Value<F>; 16]; BLOCKS],
    input_size: Value<F>,
}

#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bChip<F>,
}

impl<F: PrimeField, const BLOCKS: usize, const OUT_LEN: usize> Circuit<F>
    for Blake2bCircuit<F, BLOCKS, OUT_LEN>
{
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
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

        let blake2b_table16_chip = Blake2bChip::configure(meta, full_number_u64, limbs);

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
            OUT_LEN,
            self.input_size,
            self.input,
        )
    }
}

impl<F: PrimeField, const BLOCKS: usize, const OUT_LEN: usize> Blake2bCircuit<F, BLOCKS, OUT_LEN> {
    pub fn new_for(input: [[Value<F>; 16]; BLOCKS], input_size: Value<F>) -> Self {
        Self {
            _ph: PhantomData,
            input,
            input_size,
        }
    }
}
