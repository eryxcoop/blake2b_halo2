use crate::types::row::AssignedRow;
use crate::types::AssignedNative;
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::Error;
use crate::types::blake2b_word::AssignedBlake2bWord;
use crate::types::byte::AssignedByte;

/// This is the trait that groups the Blake2b implementation chips. Every Blake2b chip
/// should implement this trait.
pub trait Blake2bInstructions: Clone {
    /// Populate all lookup tables needed for the chip
    fn populate_lookup_tables<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    /// Assign initializations constants at the beginning. These constants are the initialization
    /// vector (IV) constants, the zero constant and a constant computed from the key and output
    /// lengths that is used for the initial state of the rounds.
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
    /// The return bytes of this function are the digest of the Blake2b computation.
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

    /// This method computes a compression round of Blake2b. The global state is update through
    /// consecutive calls of this method. If the algorithm is in its last round, the is_last_block
    /// parameter should be set to true.
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
    /// One round of compress has 96 mixing rounds.
    /// * 'x' and 'y' are the variables that hold the AssignedCell with the input values that will
    /// be processed in this mixing round.
    /// The 'state_indexes' are the indexes of the compress state that will take part on this
    /// mixing round. These are also needed to update the state at the end of the mixing.
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
    /// processes 128 bytes, or as we represent them: 16 words of 64 bits. Here is also where
    /// padding is applied, that's why the method needs data like if this is the last block,
    /// or if it's the block holding the key.
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
