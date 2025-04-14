use crate::blake2b::chips::blake2b_instructions::Blake2bInstructions;
use crate::base_operations::types::AssignedNative;
use ff::PrimeField;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;
use crate::base_operations::types::byte::AssignedByte;
use crate::blake2b::chips::utils::enforce_input_sizes;

/// A gadget that constrains a Blake2b invocation. This interface works with
/// in/out consisting of AssignedNative. The algorithm expects its values to be in the range of
/// a Byte, and will fail if they're not.
///
/// The gadget is parametrised with a chip that implements [Blake2bInstructions].
/// There is currently one implementation of the instruction set:
/// * [Blake2bChip] This chip uses a lookup table of size `2**16`. This means
///   that all circuits instantiating this chip will be at least `2**17` rows,
///   as we need to padd the circuit to provide ZK. This chip achieves a Blake2b
///   digest in 2469 rows.
pub struct Blake2b<C: Blake2bInstructions> {
    chip: C,
}

impl<C: Blake2bInstructions> Blake2b<C> {
    /// Create a new hasher instance.
    pub fn new(chip: C) -> Result<Self, Error> {
        Ok(Self { chip })
    }

    /// This method should be called only once in the circuit to initialize the chip's lookup tables
    pub fn initialize<F: PrimeField>(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.chip.populate_lookup_tables(layouter)
    }

    /// Main method of the Gadget. The 'input' and 'key' cells should be filled with byte values.
    pub fn hash<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &[AssignedNative<F>],
        key: &[AssignedNative<F>],
        output_size: usize,
    ) -> Result<[AssignedByte<F>; 64], Error> {
        enforce_input_sizes(output_size, key.len());
        /// All the computation is performed inside a single region
        // TODO: experiment with a region per Mix of Compress, instead of a single region
        layouter.assign_region(
            || "single region",
            |mut region| {
                /// Initialize in 0 the offset for the advice cells in the region
                let mut advice_offset: usize = 0;

                let (iv_constant_cells, initial_state_0, zero_constant) =
                    self.chip.assign_constant_advice_cells(
                        output_size,
                        key.len(),
                        &mut region,
                        &mut advice_offset,
                    )?;

                let mut initial_global_state =
                    self.chip.compute_initial_state(&iv_constant_cells, initial_state_0)?;

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
