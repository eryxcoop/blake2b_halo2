use crate::blake2b::blake2b::Blake2b;
use crate::blake2b::chips::blake2b_instructions::Blake2bInstructions;
use crate::types::{AssignedByte, AssignedElement};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};
use std::array;
use std::marker::PhantomData;

/// This is an example circuit of how you should use the Blake2b chip.
#[derive(Clone)]
pub struct Blake2bCircuit<F: PrimeField, OptimizationChip: Blake2bInstructions> {
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
pub struct Blake2bConfig<F: PrimeField, OptimizationChip: Blake2bInstructions> {
    _ph: PhantomData<F>,
    /// The chip that will be used to compute the hash. We only need this.
    blake2b_chip: OptimizationChip,
    /// Column that will hold the expected output of the hash in the form of public inputs
    expected_final_state: Column<Instance>,
    limbs: [Column<Advice>; 8],
}

impl<F: PrimeField, OptimizationChip: Blake2bInstructions> Circuit<F>
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
            limbs
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        /// The input bytes are assigned in the circuit before calling the hash function.
        /// They're not constrained to be in the range [0,255] here, but they are when used inside
        /// the blake2b chip. This means that the chip does not expect the inputs to be bytes, but
        /// the execution will fail if they're not.
        let assigned_input = Self::assign_inputs_to_the_trace(config.clone(), &mut layouter, &self.input)?;
        let assigned_key = Self::assign_inputs_to_the_trace(config.clone(), &mut layouter, &self.key)?;

        /// The initialization function should be called before the hash computation. For many hash
        /// computations it should be called only once.
        let mut blake2b = Blake2b::new(config.blake2b_chip)?;
        blake2b.initialize(&mut layouter)?;

        /// Call to the blake2b function
        let result = blake2b.hash(&mut layouter, &assigned_input, &assigned_key, self.output_size)?;

        /// Assert results
        blake2b.constrain_result(
            &mut layouter,
            result,
            config.expected_final_state,
            self.output_size,
        )
    }
}

impl<F: PrimeField, OptimizationChip: Blake2bInstructions> Blake2bCircuit<F, OptimizationChip> {
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

    /// Here the inputs are stored in the trace. It doesn't really matter how they're stored, this
    /// specific circuit uses the limb columns to do it but that's arbitrary.
    fn assign_inputs_to_the_trace(
        config: Blake2bConfig<F, OptimizationChip>,
        layouter: &mut impl Layouter<F>,
        input: &[Value<F>],
    ) -> Result<Vec<AssignedByte<F>>, Error> {
        let result = layouter.assign_region(|| "Inputs", |mut region|{
            let inner_result = input.into_iter().enumerate().map(|(index, input_byte)|{
                let row = index / 8;
                let column = index % 8;
                AssignedByte::<F>::new(region.assign_advice(
                    || format!("Input column: {}, row: {}", row, column),
                    config.limbs[column],
                    row,
                    || *input_byte
                ).unwrap())
            }).collect::<Vec<_>>().try_into().unwrap();
            Ok(inner_result)
        })?;
        Ok(result)
    }
}
