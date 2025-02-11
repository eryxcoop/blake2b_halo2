use super::*;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use crate::chips::blake2b_implementations::blake2b_chip::Blake2bChip;

pub struct Blake2bCircuit<F: Field> {
    _ph: PhantomData<F>,
    input: Vec<Value<F>>,
    input_size: usize,
    key: Vec<Value<F>>,
    key_size: usize,
    output_size: usize,
}

#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bChip<F>,
}

impl<F: PrimeField> Circuit<F> for Blake2bCircuit<F> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let input_size = self.input_size;
        let key_size = self.key_size;
        Self {
            _ph: PhantomData,
            input: vec![Value::unknown(); input_size],
            input_size,
            key: vec![Value::unknown(); key_size],
            key_size,
            output_size: self.output_size,
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
            self.output_size,
            self.input_size,
            self.key_size,
            &self.input,
            &self.key,
        )
    }
}

impl<F: PrimeField> Blake2bCircuit<F> {
    pub fn new_for(input: Vec<Value<F>>, input_size: usize, key: Vec<Value<F>>, key_size: usize, output_size: usize) -> Self {
        Self {
            _ph: PhantomData,
            input,
            input_size,
            key,
            key_size,
            output_size,
        }
    }
}
