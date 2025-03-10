use super::*;

/// The set of instructions that every Blake2b chip should implement
pub trait Blake2bInstructions<F: PrimeField>: Clone {
    /// Configuration of the circuit, this includes initialization of all the necessary configs.
    /// Some of them are general for every implementation, some are optimization-specific.
    /// It should be called in the configuration of the user circuit.
    fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self;

    /// Initialization of the circuit. This will usually create the needed lookup tables for the
    /// specific optimization. This should be called on the synthesize of the circuit but only once.
    fn initialize_with(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

    /// Execution of the algorithm for a set of given inputs in the context of a circuit.
    /// This should be called on the synthesize of the circuit for each desired hash.
    fn compute_blake2b_hash_for_inputs(
        &mut self,
        layouter: &mut impl Layouter<F>,
        output_size: usize,
        input_size: usize,
        key_size: usize,
        input: &[Value<F>],
        key: &[Value<F>],
    ) -> Result<(), Error>;
}
