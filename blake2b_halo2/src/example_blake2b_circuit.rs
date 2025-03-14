use ff::PrimeField;
use std::marker::PhantomData;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use std::array;
use crate::blake2b::chips::blake2b_generic::Blake2bGeneric;

/// This is an example circuit of how you should use the Blake2b chip.
#[derive(Clone)]
pub struct Blake2bCircuit<F: PrimeField, OptimizationChip: Blake2bGeneric> {
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
pub struct Blake2bConfig<F: PrimeField, OptimizationChip: Blake2bGeneric> {
    _ph: PhantomData<F>,
    /// The chip that will be used to compute the hash. We only need this.
    blake2b_chip: OptimizationChip,
    expected_final_state: Column<Instance>,
}

impl<F: PrimeField, OptimizationChip: Blake2bGeneric> Circuit<F>
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

        let expected_final_state = meta.instance_column();
        meta.enable_equality(expected_final_state);

        /// We need to provide the chip with the advice columns that it will use.
        let blake2b_chip = OptimizationChip::configure(meta, full_number_u64, limbs);

        Self::Config {
            _ph: PhantomData,
            blake2b_chip,
            expected_final_state,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        /// The initialization function should be called before the hash computation. For many hash
        /// computations it should be called only once.
        config.blake2b_chip.initialize_with(&mut layouter)?;

        /// Call to the blake2b function
        let result_cells = config.blake2b_chip.compute_blake2b_hash_for_inputs(
            &mut layouter,
            self.output_size,
            self.input_size,
            self.key_size,
            &self.input,
            &self.key,
        )?;

        /// Assert results
        config.blake2b_chip.constraint_public_inputs_to_equal_computation_results(
            &mut layouter,
            result_cells,
            self.output_size,
            config.expected_final_state,
        )
    }
}

impl<F: PrimeField, OptimizationChip: Blake2bGeneric> Blake2bCircuit<F, OptimizationChip> {
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
