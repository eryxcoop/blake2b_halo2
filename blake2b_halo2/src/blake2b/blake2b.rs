use crate::blake2b::chips::blake2b_instructions::Blake2bInstructions;
use crate::types::{AssignedByte};
use ff::PrimeField;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;
use crate::blake2b::chips::utils::enforce_input_sizes;

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
        input: &[AssignedByte<F>],
        key: &[AssignedByte<F>],
        output_size: usize,
    ) -> Result<[AssignedByte<F>; 64], Error> {
        enforce_input_sizes(output_size, key.len());
        /// All the computation is performed inside a single region. Some optimizations take advantage
        /// of this fact, since we want to avoid copying cells between regions.
        // [inigo] Which optimisations could not be applied if we split this into different regions, e.g.
        // one per compression round?
        layouter.assign_region(
            || "single region",
            |mut region| {
                /// Initialize in 0 the offset for the advice cells in the region
                let mut advice_offset: usize = 0;

                let (
                    iv_constant_cells,
                    output_size_constant,
                    zero_constant,
                ) = self.chip.assign_constant_advice_cells(
                    output_size,
                    key.len(),
                    &mut region,
                    &mut advice_offset,
                )?;

                let mut initial_global_state = self.chip.compute_initial_state(
                    &iv_constant_cells,
                    output_size_constant,
                )?;

                self.chip.perform_blake2b_iterations(
                    &mut region,
                    &mut advice_offset,
                    &input,
                    &key,
                    &iv_constant_cells,
                    &mut initial_global_state,
                    zero_constant,
                )
            },
        )
    }
}
