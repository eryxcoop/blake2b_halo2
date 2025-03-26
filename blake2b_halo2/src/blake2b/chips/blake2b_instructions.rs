use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::blake2b::chips::utils::{compute_processed_bytes_count_value_for_iteration, constrain_padding_cells_to_equal_zero, full_number_of_each_state_row, get_total_blocks_count, ABCD, BLAKE2B_BLOCK_SIZE, IV_CONSTANTS, SIGMA};
use crate::types::AssignedRow;
use crate::types::{AssignedBlake2bWord, AssignedByte, AssignedNative};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};

/// This is the trait that groups the Blake2b implementation chips.
pub trait Blake2bInstructions: Clone {
    /// Configuration of the circuit, this includes initialization of all the necessary configs.
    /// Some of them are general for every implementation, some are optimization-specific.
    /// It should be called in the configuration of the user circuit.
    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self;

    /// Populate all lookup tables needed for the chip
    fn populate_lookup_tables<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    // ---------- MAIN METHODS ---------- //

    /// Assign all the constants at the beginning
    fn assign_constant_advice_cells<F: PrimeField>(
        &self,
        output_size: usize,
        key_size: usize,
        mut region: &mut Region<F>,
        advice_offset: &mut usize,
    ) -> Result<([AssignedBlake2bWord<F>; 8], AssignedBlake2bWord<F>, AssignedNative<F>), Error> {
        let iv_constant_cells: [AssignedBlake2bWord<F>; 8] =
            self.assign_iv_constants_to_fixed_cells(&mut region, advice_offset)?;

        let zero_constant = self.assign_limb_constant_u64(
            region, advice_offset, "zero", 0, 0)?.into();

        let iv_constant_0 = IV_CONSTANTS[0];
        let out_len = output_size as u64;
        const INIT_CONST_STATE_0: u64 = 0x01010000u64;
        let key_size_shifted= (key_size as u64) << 8;
        // state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        let initial_state_index_0 = iv_constant_0 ^ INIT_CONST_STATE_0 ^ key_size_shifted ^ out_len;

        let initial_state_0 = self.assign_limb_constant_u64(
                region,
                advice_offset,
                "initial state index 0",
                initial_state_index_0,
                1,
        )?;

        *advice_offset += 1;

        Ok((
            iv_constant_cells,
            initial_state_0,
            zero_constant,
        ))
    }

    /// This method handles the part of the configuration that is generic to all optimizations.
    /// Most of the operations are performed the same way in all optimizations.
    fn generic_configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> (Decompose8Config, LimbRotation, Rotate63Config, NegateConfig) {
        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);
        let rotate_63_config = Rotate63Config::configure(meta, full_number_u64);
        let negate_config = NegateConfig::configure(meta, full_number_u64);

        let constants = meta.fixed_column();
        meta.enable_equality(constants);
        meta.enable_constant(constants);

        (decompose_8_config, LimbRotation, rotate_63_config, negate_config)
    }

    /// Computes the initial global state of Blake2b. It only depends on the key size and the
    /// output size, which are values known at circuit building time.
    fn compute_initial_state<F: PrimeField>(
        &self,
        iv_constant_cells: &[AssignedBlake2bWord<F>; 8],
        initial_state_0: AssignedBlake2bWord<F>,
    ) -> Result<[AssignedBlake2bWord<F>; 8], Error> {
        let mut global_state = iv_constant_cells.clone();
        global_state[0] = initial_state_0;
        Ok(global_state)
    }

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
        input: &[AssignedByte<F>],
        key: &[AssignedByte<F>],
        iv_constants: &[AssignedBlake2bWord<F>; 8],
        global_state: &mut [AssignedBlake2bWord<F>; 8],
        zero_constant_cell: AssignedNative<F>,
    ) -> Result<[AssignedByte<F>; 64], Error> {
        let input_size = input.len();
        let is_key_empty = key.is_empty();
        let is_input_empty = input_size == 0;

        let input_blocks = input_size.div_ceil(BLAKE2B_BLOCK_SIZE);
        let total_blocks = get_total_blocks_count(input_blocks, is_input_empty, is_key_empty);
        let last_input_block_index = if is_input_empty { 0 } else { input_blocks - 1 };

        /// Main loop
        (0..total_blocks)
            .map(|i| {
                let is_last_block = i == total_blocks - 1;
                let is_key_block = !is_key_empty && i == 0;

                /// This is an intermediate value in the Blake2b algorithm. It represents the amount of
                /// bytes processed so far.
                let processed_bytes_count = compute_processed_bytes_count_value_for_iteration(
                    i,
                    is_last_block,
                    input_size,
                    is_key_empty,
                );

                let current_block_rows = self.build_current_block_rows(
                    region,
                    advice_offset,
                    &input,
                    &key,
                    i,
                    last_input_block_index,
                    is_key_empty,
                    is_last_block,
                    is_key_block,
                    zero_constant_cell.clone(),
                )?;

                /// Padding for the last block, in case the key block is not the only one.
                if is_last_block && !is_key_block {
                    let zeros_amount_for_input_padding = if input_size == 0 {
                        128
                    } else {
                        // Complete the block with zeroes
                        (BLAKE2B_BLOCK_SIZE - input_size % BLAKE2B_BLOCK_SIZE) % BLAKE2B_BLOCK_SIZE
                    };
                    constrain_padding_cells_to_equal_zero(
                        region,
                        zeros_amount_for_input_padding,
                        &current_block_rows,
                        &zero_constant_cell,
                    )?;
                }
                /// Padding for the key block, in all cases that it exists. It is always the first block.
                if is_key_block {
                    /// Complete the block with zeroes
                    let zeros_amount_for_key_padding = BLAKE2B_BLOCK_SIZE - key.len();
                    constrain_padding_cells_to_equal_zero(
                        region,
                        zeros_amount_for_key_padding,
                        &current_block_rows,
                        &zero_constant_cell,
                    )?;
                }

                let current_block_cells = full_number_of_each_state_row(current_block_rows);

                self.compress(
                    region,
                    advice_offset,
                    iv_constants,
                    global_state,
                    current_block_cells,
                    processed_bytes_count,
                    is_last_block,
                )
            })
            .last()
            .unwrap_or_else(|| Err(Error::Synthesis))
    }

    /// This method computes a compression round of Blake2b. If the algorithm is in its last round,
    /// the is_last_block parameter should be set to true.
    #[allow(clippy::too_many_arguments)]
    fn compress<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &mut usize,
        iv_constants: &[AssignedBlake2bWord<F>; 8],
        global_state: &mut [AssignedBlake2bWord<F>; 8],
        current_block_cells: [AssignedBlake2bWord<F>; 16],
        processed_bytes_count: u64,
        is_last_block: bool,
    ) -> Result<[AssignedByte<F>; 64], Error> {
        let mut state_vector: Vec<AssignedBlake2bWord<F>> = Vec::new();
        state_vector.extend_from_slice(global_state);
        state_vector.extend_from_slice(iv_constants);

        let mut state: [AssignedBlake2bWord<F>; 16] = state_vector.try_into().unwrap();

        // accumulative_state[12] ^= processed_bytes_count
        // Since accumulative_state[12] is allways IV_CONSTANTS[4] at this point in execution
        // and processed_bytes_count is public for both parties, the xor between both values
        // is also a constant.
        let new_state_12 = processed_bytes_count ^ IV_CONSTANTS[4];
        state[12] = self.assign_full_number_constant(region, row_offset, "New state[12]", new_state_12)?;
        *row_offset += 1;

        if is_last_block {
            state[14] = self.not(&state[14], region, row_offset)?;
        }

        /// Main loop
        for i in 0..12 {
            for j in 0..8 {
                self.mix(
                    ABCD[j][0],
                    ABCD[j][1],
                    ABCD[j][2],
                    ABCD[j][3],
                    SIGMA[i][2 * j],
                    SIGMA[i][2 * j + 1],
                    &mut state,
                    &current_block_cells,
                    region,
                    row_offset,
                )?;
            }
        }

        let mut global_state_bytes: Vec<AssignedByte<F>> = Vec::new();
        for i in 0..8 {
            global_state[i] = self.xor(&global_state[i], &state[i], region, row_offset)?;
            let row =
                self.xor_and_return_full_row(&global_state[i], &state[i + 8], region, row_offset)?;
            let mut row_limbs: Vec<_> = row.limbs.try_into().unwrap();
            global_state_bytes.append(&mut row_limbs);
            global_state[i] = row.full_number;
        }
        let global_state_bytes_array = global_state_bytes.try_into().unwrap();
        Ok(global_state_bytes_array)
    }

    /// This method computes a single round of mixing for the Blake2b algorithm.
    /// One round of compress has 96 mixing rounds
    #[allow(clippy::too_many_arguments)]
    fn mix<F: PrimeField>(
        &self,
        a_index: usize,
        b_index: usize,
        c_index: usize,
        d_index: usize,
        sigma_even: usize,
        sigma_odd: usize,
        state: &mut [AssignedBlake2bWord<F>; 16],
        current_block_words: &[AssignedBlake2bWord<F>; 16],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    // ----- Basic operations ----- //

    fn not<F: PrimeField>(
        &self,
        input_cell: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    /// In this case we need to perform the xor operation and return the entire row, because we
    /// need it to constrain the result.
    fn xor_and_return_full_row<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error>;

    fn xor<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    fn add<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    fn rotate_right_63<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    fn rotate_right_16<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    fn rotate_right_24<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    fn rotate_right_32<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    // ----- Auxiliar methods ----- //

    fn assign_full_number_constant<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &usize,
        description: &str,
        constant: u64
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    fn assign_limb_constant_u64<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &usize,
        description: &str,
        constant: u64,
        limb_index: usize
    ) -> Result<AssignedBlake2bWord<F>, Error>;

    /// Blake2b uses an initialization vector (iv) that is hardcoded. This method assigns those
    /// values to fixed cells to use later on.
    fn assign_iv_constants_to_fixed_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedBlake2bWord<F>; 8], Error> {
        let ret: [AssignedBlake2bWord<F>; 8] = IV_CONSTANTS
            .iter()
            .enumerate()
            .map(|(index, constant)| {
                self.assign_limb_constant_u64(
                    region,
                    offset,
                    "iv constants",
                    *constant,
                    index
                ).unwrap()
            })
            .collect::<Vec<AssignedBlake2bWord<F>>>()
            .try_into()
            .unwrap();
        *offset += 1;
        Ok(ret)
    }

    /// This is the part where the inputs/key are organized inside the trace. Each iteration
    /// processes 128 bytes, or as we represent them: 16 words of 64 bits.
    #[allow(clippy::too_many_arguments)]
    fn build_current_block_rows<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &[AssignedByte<F>],
        key: &[AssignedByte<F>],
        block_number: usize,
        last_input_block_index: usize,
        is_key_empty: bool,
        is_last_block: bool,
        is_key_block: bool,
        zero_constant_cell: AssignedNative<F>,
    ) -> Result<[Vec<AssignedBlake2bWord<F>>; 16], Error>;
}
