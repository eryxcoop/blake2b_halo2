use super::*;

/// We have a single chip holding 3 optimizations, which is Blake2bChip. That chip uses features to
/// switch between different optimizations.
/// In order to benchmark the 3 optimizations at the same time, we decided to unfold that chip
/// into 3 chips that don't need to use rust features. This way we can compile the 3 of them at the
/// same time which makes the Criterion report automatizable. Ideally we should find a way to do
/// this without duplicated code.
///
/// This is the trait that groups the 4 chips.
pub trait Blake2bInstructions<F: PrimeField>: Clone {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self;

    fn initialize_with(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

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
