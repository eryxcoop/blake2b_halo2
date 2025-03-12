use super::*;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use crate::blake2b::instructions::Blake2bInstructions;

/// This is an example circuit of how you should use the Blake2b chip.
/// This example here is strange. You should have this either in a test or example.
#[derive(Clone)]
pub struct Blake2bCircuit<F: PrimeField, OptimizationChip: Blake2bInstructions<F>> {
    _ph2: PhantomData<OptimizationChip>,
    /// The input and the key should be unknown for the verifier.
    input: Vec<Value<F>>,
    key: Vec<Value<F>>,
    /// All the sizes should be known at circuit building time, so we don't store them as values.
    input_size: usize,
    key_size: usize,
    output_size: usize,
}

#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField, OptimizationChip: Blake2bInstructions<F>> {
    _ph: PhantomData<F>,
    /// The chip that will be used to compute the hash. We only need this.
    blake2b_chip: OptimizationChip,
}

impl<F: PrimeField, OptimizationChip: Blake2bInstructions<F>> Circuit<F>
    for Blake2bCircuit<F, OptimizationChip>
{
    type Config = Blake2bConfig<F, OptimizationChip>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let input_size = self.input_size;
        let key_size = self.key_size;
        let output_size = self.output_size;
        Self {
            _ph2: PhantomData,
            input: vec![Value::unknown(); input_size],
            input_size,
            key: vec![Value::unknown(); key_size],
            key_size,
            output_size,
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

        /// We need to provide the chip with the advice columns that it will use.
        let blake2b_chip = OptimizationChip::configure(meta, full_number_u64, limbs);

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
        /// The initialization function should be called before the hash computation. For many hash
        /// computations it should be called only once.
        config.blake2b_chip.initialize_with(&mut layouter)?;
        config.blake2b_chip.compute_blake2b_hash_for_inputs(
            &mut layouter,
            self.output_size,
            self.input_size,
            self.key_size,
            &self.input,
            &self.key,
        )
    }
}

impl<F: PrimeField, OptimizationChip: Blake2bInstructions<F>> Blake2bCircuit<F, OptimizationChip> {
    pub fn new_for(
        input: Vec<Value<F>>,
        input_size: usize,
        key: Vec<Value<F>>,
        key_size: usize,
        output_size: usize,
    ) -> Self {
        Self {
            _ph2: PhantomData,
            input,
            input_size,
            key,
            key_size,
            output_size,
        }
    }
}
