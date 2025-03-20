use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Column, Error, Instance};
use crate::blake2b::chips::blake2b_generic::Blake2bInstructions;

/// Main gadget to compute Blake2b hash function
pub struct Blake2b<C: Blake2bInstructions> {
    chip: C,
}

impl<C: Blake2bInstructions> Blake2b<C> {
    pub fn new(chip: C) -> Result<Self, Error> {
        Ok(Self { chip })
    }

    /// This method should be called only once in the circuit
    pub fn initialize<F: PrimeField>(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.chip.populate_lookup_tables(layouter)
    }

    pub fn hash<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        // [inigo] what if we want to use the input somewhere else in the circuit?
        input: &[Value<F>],
        key: &[Value<F>],
        output_size: usize,
    ) -> Result<[AssignedCell<F, F>; 64], Error> {
        self.chip.compute_blake2b_hash_for_inputs(
            layouter,
            output_size,
            input.len(),
            key.len(),
            input,
            key,
        )
    }

    /// This is optional, the circuit can opt not to check the result if the hash digest is to
    /// remain private. This just establishes copy constraints between the expected result and the
    /// obtained digest
    pub fn constrain_result<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        global_state_bytes: [AssignedCell<F, F>; 64],
        instance_column: Column<Instance>,
        output_size: usize,
    ) -> Result<(), Error> {
        self.chip.constrain_instance(
            layouter,
            global_state_bytes,
            output_size,
            instance_column,
        )
    }
}
