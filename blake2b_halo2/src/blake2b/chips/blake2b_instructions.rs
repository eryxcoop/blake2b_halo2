use crate::types::AssignedRow;
use crate::types::{AssignedBlake2bWord, AssignedByte, AssignedNative};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::Error;

/// This is the trait that groups the Blake2b implementation chips.
pub trait Blake2bInstructions: Clone {
    /// Populate all lookup tables needed for the chip
    fn populate_lookup_tables<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    /// Assign all the constants at the beginning
    fn assign_constant_advice_cells<F: PrimeField>(
        &self,
        output_size: usize,
        key_size: usize,
        region: &mut Region<F>,
        advice_offset: &mut usize,
    ) -> Result<([AssignedBlake2bWord<F>; 8], AssignedBlake2bWord<F>, AssignedNative<F>), Error>;

    /// Computes the initial global state of Blake2b. It only depends on the key size and the
    /// output size, which are values known at circuit building time.
    fn compute_initial_state<F: PrimeField>(
        &self,
        iv_constant_cells: &[AssignedBlake2bWord<F>; 8],
        initial_state_0: AssignedBlake2bWord<F>,
    ) -> Result<[AssignedBlake2bWord<F>; 8], Error>;

    /// Here occurs the top loop of the hash function. It iterates for each block of the input and
    /// key, compressing the block and updating the global state.
    /// The global state corresponds to 8 cells containing 64-bit numbers, which are updated when
    /// some of those words change. A change in a state value is represented by changing the cell
    /// that represent that particular word in the state.
    #[allow(clippy::too_many_arguments)]
    fn perform_blake2b_iterations<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        advice_offset: &mut usize,
        input: &[AssignedNative<F>],
        key: &[AssignedNative<F>],
        iv_constants: &[AssignedBlake2bWord<F>; 8],
        global_state: &mut [AssignedBlake2bWord<F>; 8],
        zero_constant_cell: AssignedNative<F>,
    ) -> Result<[AssignedByte<F>; 64], Error>;

    /// This method computes a compression round of Blake2b. If the algorithm is in its last round,
    /// the is_last_block parameter should be set to true.
    #[allow(clippy::too_many_arguments)]
    fn compress<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &mut usize,
        iv_constants: &[AssignedBlake2bWord<F>; 8],
        global_state: &mut [AssignedBlake2bWord<F>; 8],
        current_block: [AssignedBlake2bWord<F>; 16],
        processed_bytes_count: u64,
        is_last_block: bool,
    ) -> Result<[AssignedByte<F>; 64], Error>;

    /// This method computes a single round of mixing for the Blake2b algorithm.
    /// One round of compress has 96 mixing rounds
    fn mix<F: PrimeField>(
        &self,
        state_indexes: [usize; 4],
        x: AssignedBlake2bWord<F>,
        y: AssignedBlake2bWord<F>,
        state: &mut [AssignedBlake2bWord<F>; 16],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<(), Error>;


    /// This is the part where the inputs/key are organized inside the trace. Each iteration
    /// processes 128 bytes, or as we represent them: 16 words of 64 bits.
    #[allow(clippy::too_many_arguments)]
    fn build_current_block_rows<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &[AssignedNative<F>],
        key: &[AssignedNative<F>],
        block_number: usize,
        last_input_block_index: usize,
        is_key_empty: bool,
        is_last_block: bool,
        is_key_block: bool,
        zero_constant_cell: AssignedNative<F>,
    ) -> Result<[AssignedRow<F>; 16], Error>;
}
