//! This is an example circuit of how you should use the Blake2b chip

use crate::blake2b::blake2b_gadget::Blake2b;
use crate::blake2b::chips::blake2b_chip::Blake2bChip;
use crate::base_operations::types::AssignedNative;
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};
use std::array;
use std::marker::PhantomData;

/// The struct of the circuit. It contains the input and key that will be hashed. Also
/// the sizes of the input, key and output.
#[derive(Clone)]
pub struct Blake2bCircuit<F: PrimeField> {
    /// The input and the key should be unknown for the verifier.
    input: Vec<Value<F>>,
    key: Vec<Value<F>>,
    /// All the sizes should be known at circuit building time, so we don't store them as values.
    input_size: usize,
    key_size: usize,
    output_size: usize,
}

/// The configuration of the circuit. It contains the chip that will be used to compute the hash and
/// the columns that will hold the expected output of the hash in the form of public inputs.
#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    /// The chip that will be used to compute the hash. We only need this.
    blake2b_chip: Blake2bChip,
    /// Column that will hold the expected output of the hash in the form of public inputs
    expected_final_state: Column<Instance>,
    limbs: [Column<Advice>; 8],
}

impl<F: PrimeField> Circuit<F> for Blake2bCircuit<F> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let input_size = self.input_size;
        let key_size = self.key_size;
        let output_size = self.output_size;
        Self {
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

        // We need to provide the chip with the advice columns that it will use.
        let blake2b_chip = Blake2bChip::configure(meta, full_number_u64, limbs);

        Self::Config {
            _ph: PhantomData,
            blake2b_chip,
            expected_final_state,
            limbs,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // The input bytes are assigned in the circuit before calling the hash function.
        // They're not constrained to be in the range [0,255] here, but they are when used inside
        // the blake2b chip. This means that the chip does not expect the inputs to be bytes, but
        // the execution will fail if they're not.
        let assigned_input =
            Self::assign_inputs_to_the_trace(config.clone(), &mut layouter, &self.input)?;
        let assigned_key =
            Self::assign_inputs_to_the_trace(config.clone(), &mut layouter, &self.key)?;

        // The initialization function should be called before the hash computation. For many hash
        // computations it should be called only once.
        let mut blake2b = Blake2b::new(config.blake2b_chip)?;
        blake2b.initialize(&mut layouter)?;

        // Call to the blake2b function
        let result =
            blake2b.hash(&mut layouter, &assigned_input, &assigned_key, self.output_size)?;

        // Assert results
        for (i, global_state_byte_cell) in result.iter().enumerate().take(self.output_size) {
            layouter.constrain_instance(
                global_state_byte_cell.cell(),
                config.expected_final_state,
                i,
            )?;
        }
        Ok(())
    }
}

impl<F: PrimeField> Blake2bCircuit<F> {
    /// This method creates a new instance of the circuit with the given input, key and output sizes.
    pub fn new_for(
        input: Vec<Value<F>>,
        input_size: usize,
        key: Vec<Value<F>>,
        key_size: usize,
        output_size: usize,
    ) -> Self {
        Self {
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
        config: Blake2bConfig<F>,
        layouter: &mut impl Layouter<F>,
        input: &[Value<F>],
    ) -> Result<Vec<AssignedNative<F>>, Error> {
        let result = layouter.assign_region(
            || "Inputs",
            |mut region| {
                let inner_result = input
                    .iter()
                    .enumerate()
                    .map(|(index, input_byte)| {
                        let row = index / 8;
                        let column = index % 8;
                        region
                            .assign_advice(
                                || format!("Input column: {}, row: {}", row, column),
                                config.limbs[column],
                                row,
                                || *input_byte,
                            )
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                Ok(inner_result)
            },
        )?;
        Ok(result)
    }
}
