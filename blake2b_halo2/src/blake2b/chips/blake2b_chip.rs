use crate::base_operations::addition_mod_64::AdditionMod64Config;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::base_operations::xor::XorConfig;
use crate::blake2b::chips::blake2b_instructions::Blake2bInstructions;
use crate::types::{AssignedBlake2bWord, AssignedByte, AssignedNative, AssignedRow, Blake2bWord};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};
use crate::blake2b::chips::utils::{
    compute_processed_bytes_count_value_for_iteration, constrain_padding_cells_to_equal_zero,
    full_number_of_each_state_row, get_total_blocks_count, ABCD, BLAKE2B_BLOCK_SIZE, IV_CONSTANTS,
    SIGMA,
};

/// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
/// It contains all the necessary chips and some extra columns.
///
/// This implementation uses addition with 8 limbs and computes xor with a table that precomputes
/// all the possible 8-bit operands. Since all operations have operands with 8-bit decompositions,
/// we can recycle some rows per iteration of the algorithm for every operation.
#[derive(Clone, Debug)]
pub struct Blake2bChip {
    /// Decomposition config
    decompose_8_config: Decompose8Config,
    /// Base oprerations configs
    addition_config: AdditionMod64Config,
    generic_limb_rotation_config: LimbRotation,
    rotate_63_config: Rotate63Config,
    xor_config: XorConfig,
    negate_config: NegateConfig,
    /// Advice columns
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
}

impl Blake2bInstructions for Blake2bChip {
    /// This optimization uses 2 tables:
    /// * A lookup table for range-checks of 8 bits: [0, 255]
    /// * A lookup table consisting of 3 columns that pre-computes the xor operation of 16 bits.
    fn populate_lookup_tables<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.populate_lookup_table_8(layouter)?;
        self.populate_xor_lookup_table(layouter)
    }

    /// Here the constants that will be used throughout the algorithm are assigned in some storage
    /// cells at the begining of the trace.
    fn assign_constant_advice_cells<F: PrimeField>(
        &self,
        output_size: usize,
        key_size: usize,
        region: &mut Region<F>,
        advice_offset: &mut usize,
    ) -> Result<([AssignedBlake2bWord<F>; 8], AssignedBlake2bWord<F>, AssignedNative<F>), Error>
    {
        let iv_constant_cells: [AssignedBlake2bWord<F>; 8] =
            self.assign_iv_constants_to_fixed_cells(region, advice_offset)?;

        let zero_constant = region.assign_advice_from_constant(
            || "zero",
            self.limbs[0],
            *advice_offset,
            F::from(0),
        )?;

        let iv_constant_0 = IV_CONSTANTS[0];
        let out_len = output_size as u64;
        const INIT_CONST_STATE_0: u64 = 0x01010000u64;
        let key_size_shifted = (key_size as u64) << 8;
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

        Ok((iv_constant_cells, initial_state_0, zero_constant))
    }

    /// The initial state is known at circuit building time because it depends on fixed constants,
    /// key size and output size.
    fn compute_initial_state<F: PrimeField>(
        &self,
        iv_constant_cells: &[AssignedBlake2bWord<F>; 8],
        initial_state_0: AssignedBlake2bWord<F>,
    ) -> Result<[AssignedBlake2bWord<F>; 8], Error> {
        let mut global_state = iv_constant_cells.clone();
        global_state[0] = initial_state_0;
        Ok(global_state)
    }

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

    fn compress<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &mut usize,
        iv_constants: &[AssignedBlake2bWord<F>; 8],
        global_state: &mut [AssignedBlake2bWord<F>; 8],
        current_block: [AssignedBlake2bWord<F>; 16],
        processed_bytes_count: u64,
        is_last_block: bool,
    ) -> Result<[AssignedByte<F>; 64], Error> {
        let mut state_vector: Vec<AssignedBlake2bWord<F>> = Vec::new();
        state_vector.extend_from_slice(global_state);
        state_vector.extend_from_slice(iv_constants);

        let mut state: [AssignedBlake2bWord<F>; 16] = state_vector.try_into().unwrap();

        // accumulative_state[12] ^= processed_bytes_count
        /// Since accumulative_state[12] is allways IV_CONSTANTS[4] at this point in execution
        /// and processed_bytes_count is public for both parties, the xor between both values
        /// is also a constant.
        let new_state_12 = processed_bytes_count ^ IV_CONSTANTS[4];
        state[12] = AssignedBlake2bWord::assign_fixed_word(
            region,
            "New state[12]",
            self.full_number_u64,
            *row_offset,
            new_state_12.into(),
        )?;
        *row_offset += 1;

        if is_last_block {
            state[14] = self.not(&state[14], region, row_offset)?;
        }

        /// Main loop
        for i in 0..12 {
            for j in 0..8 {
                self.mix(
                    [ABCD[j][0], ABCD[j][1], ABCD[j][2], ABCD[j][3]],
                    current_block[SIGMA[i][2 * j]].clone(),
                    current_block[SIGMA[i][2 * j + 1]].clone(),
                    &mut state,
                    region,
                    row_offset,
                )?;
            }
        }

        let mut global_state_bytes: Vec<AssignedByte<F>> = Vec::new();
        for i in 0..8 {
            global_state[i] =
                self.xor(&global_state[i], &state[i], region, row_offset)?.full_number;
            let row = self.xor(&global_state[i], &state[i + 8], region, row_offset)?;
            let mut row_limbs: Vec<_> = row.limbs.try_into().unwrap();
            global_state_bytes.append(&mut row_limbs);
            global_state[i] = row.full_number;
        }
        let global_state_bytes_array = global_state_bytes.try_into().unwrap();
        Ok(global_state_bytes_array)
    }

    fn mix<F: PrimeField>(
        &self,
        state_indexes: [usize; 4],
        x: AssignedBlake2bWord<F>,
        y: AssignedBlake2bWord<F>,
        state: &mut [AssignedBlake2bWord<F>; 16],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let v_a = &state[state_indexes[0]];
        let v_b = &state[state_indexes[1]];
        let v_c = &state[state_indexes[2]];
        let v_d = &state[state_indexes[3]];

        // v[a] = ((v[a] as u128 + v[b] as u128 + x as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add(&v_a, &v_b, region, offset)?;
        let a = self.add_copying_one_parameter(&a_plus_b, &x, region, offset)?;

        // v[d] = rotr_64(v[d] ^ v[a], 32);
        let d_xor_a = self.xor_copying_one_parameter(&a, &v_d, region, offset)?;
        let d = self.rotate_right_32(d_xor_a, region, offset)?;

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add_copying_one_parameter(&d, &v_c, region, offset)?;

        // v[b] = rotr_64(v[b] ^ v[c], 24);
        let b_xor_c = self.xor_copying_one_parameter(&c, &v_b, region, offset)?;
        let b = self.rotate_right_24(b_xor_c, region, offset)?;

        // v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add_copying_one_parameter(&b, &a, region, offset)?;
        let a = self.add_copying_one_parameter(&a_plus_b, &y, region, offset)?;

        // v[d] = rotr_64(v[d] ^ v[a], 16);
        let d_xor_a = self.xor_copying_one_parameter(&a, &d, region, offset)?;
        let d = self.rotate_right_16(d_xor_a, region, offset)?;

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add_copying_one_parameter(&d, &c, region, offset)?;

        // v[b] = rotr_64(v[b] ^ v[c], 63);
        let b_xor_c = self.xor_copying_one_parameter(&c, &b, region, offset)?;
        let b = self.rotate_right_63(b_xor_c.full_number, region, offset)?;

        state[state_indexes[0]] = a;
        state[state_indexes[1]] = b;
        state[state_indexes[2]] = c;
        state[state_indexes[3]] = d;

        Ok(())
    }

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
    ) -> Result<[AssignedRow<F>; 16], Error> {
        let current_block_values = Self::build_values_for_current_block(
            input,
            key,
            block_number,
            last_input_block_index,
            is_key_empty,
            is_last_block,
            is_key_block,
            zero_constant_cell,
        );

        self.block_words_from_bytes(region, offset, current_block_values.try_into().unwrap())
    }
}

impl Blake2bChip {
    /// Configuration of the circuit, this includes initialization of all the necessary configs.
    /// It should be called in the configuration of the user circuit before instantiating the
    /// Blake2b gadget.
    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        /// Config that is the same for every optimization
        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);
        let rotate_63_config = Rotate63Config::configure(meta, full_number_u64);
        let negate_config = NegateConfig::configure(meta, full_number_u64);

        let constants = meta.fixed_column();
        meta.enable_equality(constants);
        meta.enable_constant(constants);

        /// Config that is optimization-specific
        /// For the carry column we'll reuse the first limb column for optimization reasons
        let addition_config = AdditionMod64Config::configure(
            meta,
            full_number_u64,
            limbs[0],
            decompose_8_config.clone(),
        );
        let xor_config = XorConfig::configure(meta, limbs, decompose_8_config.clone());

        Self {
            addition_config,
            decompose_8_config,
            generic_limb_rotation_config: LimbRotation,
            rotate_63_config,
            xor_config,
            negate_config,
            full_number_u64,
            limbs,
        }
    }

    /// Blake2b uses a fixed initialization vector (iv). This method assigns those
    /// fixed values to advice cells. The cells used are the 8 limbs in the very first row of the
    /// trace. This is implementation specific.
    fn assign_iv_constants_to_fixed_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedBlake2bWord<F>; 8], Error> {
        let ret: [AssignedBlake2bWord<F>; 8] = IV_CONSTANTS
            .iter()
            .enumerate()
            .map(|(index, constant)| {
                self.assign_limb_constant_u64(region, offset, "iv constants", *constant, index)
                    .unwrap()
            })
            .collect::<Vec<AssignedBlake2bWord<F>>>()
            .try_into()
            .unwrap();
        *offset += 1;
        Ok(ret)
    }

    /// Bitwise negation operation. This is used only once in the circuit, at the beginning of the
    /// last compress iteration. It's implemented through a [NegateConfig] which establishes all the
    /// necessary restrictions.
    fn not<F: PrimeField>(
        &self,
        input_cell: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.negate_config.generate_rows_from_cell(region, offset, input_cell, self.full_number_u64)
    }

    /// Bitwise xor operation. It's performed over two assigned blake2b words. Is one of the most
    /// used operations in the Blake2b function and implemented through a [XorConfig] which
    /// creates all the necessary lookups.
    fn xor<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.xor_config.generate_xor_rows_from_cells(region, offset, lhs, rhs, false)
    }

    /// Addition operation. It's performed over two assigned blake2b words. Is one of the most
    /// used operations in the Blake2b function and implemented through a [AdditionMod64Config]
    /// which creates all the necessary lookups.
    fn add<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let addition_cell = self
            .addition_config
            .generate_addition_rows_from_cells(
                region,
                offset,
                lhs,
                rhs,
                false,
                self.full_number_u64,
            )?
            .0
            .clone();
        Ok(addition_cell)
    }

    /// Bitwise rotation mod 64 bits. 63 bits to the right. Internally uses a [Rotate63Config] and
    /// only receives the full number as input because it doesn't need the limbs to establish the
    /// necessary restrictions.
    fn rotate_right_63<F: PrimeField>(
        &self,
        input: AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.rotate_63_config.generate_rotation_rows_from_cells(
            region,
            offset,
            &input,
            self.full_number_u64,
        )
    }

    /// Bitwise rotation mod 64 bits. 16 bits to the right. Internally uses the [LimbRotation] gate
    /// and receives an [AssignedRow] as input because it needs the limbs to establish the
    /// necessary restrictions. It only returns the full number, not the resulting row.
    fn rotate_right_16<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.generic_limb_rotation_config.generate_rotation_rows_from_input_row(
            region,
            offset,
            &self.decompose_8_config,
            input_row,
            2,
            self.full_number_u64,
            self.limbs,
        )
    }

    /// Bitwise rotation mod 64 bits. 24 bits to the right. Internally uses the [LimbRotation] gate
    /// and receives an [AssignedRow] as input because it needs the limbs to establish the
    /// necessary restrictions. It only returns the full number, not the resulting row.
    fn rotate_right_24<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.generic_limb_rotation_config.generate_rotation_rows_from_input_row(
            region,
            offset,
            &self.decompose_8_config,
            input_row,
            3,
            self.full_number_u64,
            self.limbs,
        )
    }

    /// Bitwise rotation mod 64 bits. 32 bits to the right. Internally uses the [LimbRotation] gate
    /// and receives an [AssignedRow] as input because it needs the limbs to establish the
    /// necessary restrictions. It only returns the full number, not the resulting row.
    fn rotate_right_32<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.generic_limb_rotation_config.generate_rotation_rows_from_input_row(
            region,
            offset,
            &self.decompose_8_config,
            input_row,
            4,
            self.full_number_u64,
            self.limbs,
        )
    }

    /// This method performs a regular [xor] operation with the difference that it returns the whole
    /// row in the trace, instead of just the cell holding the full value. This allows an optimization
    /// where the next operation (which is a rotation) can just read the limbs directly and apply
    /// the limb rotation without copying them.
    fn xor_copying_one_parameter<F: PrimeField>(
        &self,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.xor_config.generate_xor_rows_from_cells(
            region,
            offset,
            previous_cell,
            cell_to_copy,
            true,
        )
    }

    /// This method behaves like [add], with the difference that it takes advantage of the fact that
    /// the last row in the circuit is one of the operands of the addition, so it only needs to copy
    /// one parameter because the other is already on the trace.
    fn add_copying_one_parameter<F: PrimeField>(
        &self,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        Ok(self
            .addition_config
            .generate_addition_rows_from_cells(
                region,
                offset,
                previous_cell,
                cell_to_copy,
                true, // Uses the optimization
                self.full_number_u64,
            )?
            .0
            .clone())
    }

    /// The 8-bit range-check lookup table is created by the [Decompose8Config], since it
    /// establishes the lookups over it.
    fn populate_lookup_table_8<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.decompose_8_config.populate_lookup_table(layouter)
    }

    /// The xor lookup table is created by the [XorConfig], since it establishes the lookups over it.
    fn populate_xor_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.xor_config.populate_xor_lookup_table(layouter)
    }

    /// Given an array of [AssignedNative] byte-values, it puts in the circuit a full row with those
    /// bytes in the limbs and the resulting full number in the first column. The resulting values
    /// are range-checked by the circuit in the [Decompose8Config].
    fn new_row_from_assigned_bytes<F: PrimeField>(
        &self,
        bytes: &[AssignedNative<F>; 8],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error> {
        let ret = self.decompose_8_config.generate_row_from_assigned_bytes(region, bytes, *offset);
        *offset += 1;
        ret
    }

    /// This method is used when building the block words from the input bytes. It receives a list
    /// of 128 [AssignedNative] bytes that still haven't been range-checked and returns a list of
    /// 16 [AssignedRow] putted in the trace, range-checked by the [Decompose8Config] and ready for
    /// use in the algorithm.
    fn block_words_from_bytes<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        block: [AssignedNative<F>; 128],
    ) -> Result<[AssignedRow<F>; 16], Error> {
        let mut current_block_rows_vector: Vec<AssignedRow<F>> = Vec::new();
        for i in 0..16 {
            let bytes: &[AssignedNative<F>; 8] = block[i * 8..(i + 1) * 8].try_into().unwrap();
            let current_row_cells = self.new_row_from_assigned_bytes(bytes, region, offset)?;
            current_block_rows_vector.push(current_row_cells);
        }
        let current_block_rows = current_block_rows_vector.try_into().unwrap();
        Ok(current_block_rows)
    }

    /// Computes the values of the current block in the blake2b algorithm, based on the input and
    /// the block number we're on, among other relevant data.
    fn build_values_for_current_block<F: PrimeField>(
        input: &[AssignedNative<F>],
        key: &[AssignedNative<F>],
        block_number: usize,
        last_input_block_index: usize,
        is_key_empty: bool,
        is_last_block: bool,
        is_key_block: bool,
        zero_constant_cell: AssignedNative<F>,
    ) -> Vec<AssignedNative<F>> {
        if is_last_block && !is_key_block {
            let mut result = input[last_input_block_index * BLAKE2B_BLOCK_SIZE..].to_vec();
            result.resize(128, zero_constant_cell);
            result
        } else if is_key_block {
            let mut result = key.to_vec();
            result.resize(128, zero_constant_cell);
            result
        } else {
            let current_input_block_index =
                if is_key_empty { block_number } else { block_number - 1 };
            input[current_input_block_index * BLAKE2B_BLOCK_SIZE
                ..(current_input_block_index + 1) * BLAKE2B_BLOCK_SIZE]
                .to_vec()
        }
    }

    /// Assigns an u64 constant to trace[row_offset][limbs[limb_index]] cell.
    fn assign_limb_constant_u64<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &usize,
        description: &str,
        constant: u64,
        limb_index: usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        AssignedBlake2bWord::assign_fixed_word(
            region,
            description,
            self.limbs[limb_index],
            *row_offset,
            constant.into(),
        )
    }
}
