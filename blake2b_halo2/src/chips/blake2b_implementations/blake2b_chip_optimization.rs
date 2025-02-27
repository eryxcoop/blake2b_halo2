use super::*;

pub trait Blake2bChipOptimization<F: PrimeField> {
    fn initialize_with(&mut self, layouter: &mut impl Layouter<F>);

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