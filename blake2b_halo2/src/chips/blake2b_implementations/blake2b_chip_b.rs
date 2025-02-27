use super::*;
use crate::auxiliar_functions::{value_for};
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::decomposition_trait::Decomposition;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::negate_chip::NegateChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed, Instance};
use num_bigint::BigUint;
use crate::chips::blake2b_implementations::blake2b_chip_optimization::Blake2bChipOptimization;
use crate::chips::xor_chip::XorChip;

type AdditionChip<F> = AdditionMod64Chip<F, 8, 10>;
const BLAKE2B_BLOCK_SIZE: usize = 128;

/// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
/// It contains all the necessary chips and some extra columns.
#[derive(Clone, Debug)]
pub struct Blake2bChipB<F: PrimeField> {
    /// Decomposition chips
    decompose_8_chip: Decompose8Chip<F>,
    /// Base oprerations chips
    addition_chip: AdditionChip<F>,
    generic_limb_rotation_chip: LimbRotationChip<F>,
    rotate_63_chip: Rotate63Chip<F, 8, 9>,
    xor_chip: XorChip<F>,
    negate_chip: NegateChip<F>,
    /// Column for constants of Blake2b
    constants: Column<Fixed>,
    /// Column for the expected final state of the hash
    expected_final_state: Column<Instance>,
}

impl <F: PrimeField> Blake2bChipOptimization<F> for Blake2bChipB<F> {
    /// This method initializes the chip with the necessary lookup tables. It should be called once
    /// before the hash computation.
    fn initialize_with(&mut self, layouter: &mut impl Layouter<F>) {
        self._populate_lookup_table_8(layouter);
        self._populate_xor_lookup_table(layouter);
    }

    /// This is the main method of the chip. It computes the Blake2b hash for the given inputs.
    fn compute_blake2b_hash_for_inputs(
        &mut self,
        layouter: &mut impl Layouter<F>,
        output_size: usize,
        input_size: usize,
        key_size: usize,
        input: &[Value<F>],
        key: &[Value<F>],
    ) -> Result<(), Error> {
        Self::_enforce_input_sizes(output_size, key_size);

        /// All the computation is performed inside a single region. Some optimizations take advantage
        /// of this fact, since we want to avoid copying cells between regions.
        let global_state_bytes = layouter.assign_region(
            || "single region",
            |mut region| {
                /// Initialize in 0 the offset for the fixed cells in the region
                let mut constants_offset: usize = 0;
                let iv_constants: [AssignedCell<F, F>; 8] =
                    self.assign_iv_constants_to_fixed_cells(&mut region, &mut constants_offset);
                let init_const_state_0 = self
                    .assign_01010000_constant_to_fixed_cell(&mut region, &mut constants_offset)?;
                let output_size_constant = self.assign_constant_to_fixed_cell(
                    &mut region,
                    &mut constants_offset,
                    output_size,
                    "output size",
                )?;
                let key_size_constant_shifted = self.assign_constant_to_fixed_cell(
                    &mut region,
                    &mut constants_offset,
                    key_size << 8,
                    "key size",
                )?;

                /// Initialize in 0 the offset for the advice cells in the region
                let mut advice_offset: usize = 0;

                let mut global_state = self.compute_initial_state(
                    &mut region,
                    &mut advice_offset,
                    &iv_constants,
                    init_const_state_0,
                    output_size_constant,
                    key_size_constant_shifted,
                )?;

                self.perform_blake2b_iterations(
                    &mut region,
                    &mut advice_offset,
                    &mut constants_offset,
                    input_size,
                    input,
                    key,
                    &iv_constants,
                    &mut global_state,
                )
            },
        )?;

        self.constraint_public_inputs_to_equal_computation_results(
            layouter,
            global_state_bytes,
            output_size,
        )
    }
}

impl<F: PrimeField> Blake2bChipB<F> {
    /// The chip does not own the advice columns it utilizes. It is the responsibility of the caller
    /// to provide them. This gives flexibility to the caller to use the same advice columns for
    /// multiple purposes.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        Self::_enforce_modulus_size();

        /// An extra carry column is needed for the sum operation with 8 limbs.
        let carry = meta.advice_column();
        let addition_chip = AdditionMod64Chip::<F, 8, 10>::configure(meta, full_number_u64, carry);

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);
        let generic_limb_rotation_chip = LimbRotationChip::new();
        let rotate_63_chip = Rotate63Chip::configure(meta, full_number_u64);

        let xor_chip = XorChip::configure(meta, limbs);

        let negate_chip = NegateChip::configure(meta, full_number_u64);

        let constants = meta.fixed_column();
        meta.enable_equality(constants);

        let expected_final_state = meta.instance_column();
        meta.enable_equality(expected_final_state);

        Self {
            addition_chip,
            decompose_8_chip,

            generic_limb_rotation_chip,
            rotate_63_chip,
            xor_chip,
            negate_chip,
            constants,
            expected_final_state,
        }
    }

    /// Enforces the output and key sizes.
    fn _enforce_input_sizes(output_size: usize, key_size: usize) {
        assert!(output_size <= 64, "Output size must be between 1 and 64 bytes");
        assert!(output_size > 0, "Output size must be between 1 and 64 bytes");
        assert!(key_size <= 64, "Key size must be between 1 and 64 bytes");
    }

    /// Enforces the field's modulus to be greater than 2^65, which is a necessary condition for the rot63 gate to be sound.
    fn _enforce_modulus_size() {
        let modulus_bytes: Vec<u8> = hex::decode(F::MODULUS.trim_start_matches("0x"))
            .expect("Modulus is not a valid hex number");
        let modulus = BigUint::from_bytes_be(&modulus_bytes);
        let two_pow_65 = BigUint::from(1u128 << 65);
        assert!(modulus > two_pow_65, "Field modulus must be greater than 2^65");
    }

    /// Computes the initial global state of Blake2b. It only depends on the key size and the
    /// output size, which are values known at circuit building time.
    fn compute_initial_state(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        iv_constants: &[AssignedCell<F, F>; 8],
        init_const_state_0: AssignedCell<F, F>,
        output_size_constant: AssignedCell<F, F>,
        key_size_constant_shifted: AssignedCell<F, F>,
    ) -> Result<[AssignedCell<F, F>; 8], Error> {
        let mut global_state = Self::iv_constants()
            .map(|constant| self.new_row_from_value(constant, region, offset).unwrap());

        Self::constrain_initial_state(region, &global_state, iv_constants)?;

        // state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        global_state[0] = self.xor(&global_state[0], &init_const_state_0, region, offset);
        global_state[0] = self.xor(&global_state[0], &output_size_constant, region, offset);
        global_state[0] = self.xor(&global_state[0], &key_size_constant_shifted, region, offset);
        Ok(global_state)
    }

    /// Here occurs the top loop of the hash function. It iterates for each block of the input and
    /// key, compressing the block and updating the global state.
    /// The global state corresponds to 8 cells containing 64-bit numbers, which are updated when
    /// some of those words change. A change in a state value is represented by changing the cell
    /// that represent that particular word in the state.
    #[allow(clippy::too_many_arguments)]
    fn perform_blake2b_iterations(
        &mut self,
        region: &mut Region<F>,
        advice_offset: &mut usize,
        constants_offset: &mut usize,
        input_size: usize,
        input: &[Value<F>],
        key: &[Value<F>],
        iv_constants: &[AssignedCell<F, F>; 8],
        global_state: &mut [AssignedCell<F, F>; 8],
    ) -> Result<[AssignedCell<F, F>; 64], Error> {
        // This is just to be able to return the result of the last compress call
        let mut global_state_bytes = Err(Error::Synthesis);

        let is_key_empty = key.is_empty();
        let is_input_empty = input_size == 0;

        let input_blocks = input_size.div_ceil(BLAKE2B_BLOCK_SIZE);
        let total_blocks = Self::get_total_blocks_count(input_blocks, is_input_empty, is_key_empty);
        let last_input_block_index = if is_input_empty { 0 } else { input_blocks - 1 };

        /// Main loop
        for i in 0..total_blocks {
            let is_last_block = i == total_blocks - 1;
            let is_key_block = !is_key_empty && i == 0;

            /// This is an intermediate value in the Blake2b algorithm. It represents the amount of
            /// bytes processed so far.
            let processed_bytes_count = Self::compute_processed_bytes_count_value_for_iteration(
                i,
                is_last_block,
                input_size,
                is_key_empty,
            );

            /// This is the part where the inputs/key are organized inside the trace. Each iteration
            /// processes 128 bytes, or as we represent them: 16 words of 64 bits.
            let current_block_rows = self.build_current_block_rows(
                region,
                advice_offset,
                input,
                key,
                i,
                last_input_block_index,
                is_key_empty,
                is_last_block,
                is_key_block,
            )?;

            let zero_constant_cell =
                self.assign_0_constant_to_fixed_cell(region, constants_offset)?;

            /// Padding for the last block, in case the key block is not the only one.
            if is_last_block && !is_key_block {
                let zeros_amount_for_input_padding = if input_size == 0 {
                    128
                } else {
                    // Complete the block with zeroes
                    (BLAKE2B_BLOCK_SIZE - input_size % BLAKE2B_BLOCK_SIZE) % BLAKE2B_BLOCK_SIZE
                };
                self.constrain_padding_cells_to_equal_zero(
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
                self.constrain_padding_cells_to_equal_zero(
                    region,
                    zeros_amount_for_key_padding,
                    &current_block_rows,
                    &zero_constant_cell,
                )?;
            }

            let current_block_cells = Self::get_full_number_of_each(current_block_rows);

            let result = self.compress(
                region,
                advice_offset,
                iv_constants,
                global_state,
                current_block_cells,
                processed_bytes_count,
                is_last_block,
            );
            global_state_bytes = result;
        }
        global_state_bytes
    }

    /// Computes the edge cases in the amount of blocks to process.
    fn get_total_blocks_count(
        input_blocks: usize,
        is_input_empty: bool,
        is_key_empty: bool,
    ) -> usize {
        if is_key_empty {
            if is_input_empty {
                // If there's no input and no key, we still need to process one block of zeroes.
                1
            } else {
                input_blocks
            }
        } else if is_input_empty {
            // If there's no input but there's key, key is processed in the first and only block.
            1
        } else {
            // Key needs to be processed in a block alone, then come the input blocks.
            input_blocks + 1
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_current_block_rows(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        input: &[Value<F>],
        key: &[Value<F>],
        block_number: usize,
        last_input_block_index: usize,
        is_key_empty: bool,
        is_last_block: bool,
        is_key_block: bool,
    ) -> Result<[Vec<AssignedCell<F, F>>; 16], Error> {
        let current_block_values = Self::build_values_for_current_block(
            input,
            key,
            block_number,
            last_input_block_index,
            is_key_empty,
            is_last_block,
            is_key_block,
        );

        let current_block_rows =
            self.block_words_from_bytes(region, offset, current_block_values.try_into().unwrap())?;
        Ok(current_block_rows)
    }

    fn build_values_for_current_block(
        input: &[Value<F>],
        key: &[Value<F>],
        block_number: usize,
        last_input_block_index: usize,
        is_key_empty: bool,
        is_last_block: bool,
        is_key_block: bool,
    ) -> Vec<Value<F>> {
        if is_last_block && !is_key_block {
            let mut result = input[last_input_block_index * BLAKE2B_BLOCK_SIZE..].to_vec();
            result.resize(128, Value::known(F::ZERO));
            result
        } else if is_key_block {
            let mut result = key.to_vec();
            result.resize(128, Value::known(F::ZERO));
            result
        } else {
            let current_input_block_index =
                if is_key_empty { block_number } else { block_number - 1 };
            input[current_input_block_index * BLAKE2B_BLOCK_SIZE
                ..(current_input_block_index + 1) * BLAKE2B_BLOCK_SIZE]
                .to_vec()
        }
    }

    fn get_full_number_of_each(
        current_block_rows: [Vec<AssignedCell<F, F>>; 16],
    ) -> [AssignedCell<F, F>; 16] {
        current_block_rows.iter().map(|row| row[0].clone()).collect::<Vec<_>>().try_into().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn compress(
        &mut self,
        region: &mut Region<F>,
        row_offset: &mut usize,
        iv_constants: &[AssignedCell<F, F>; 8],
        global_state: &mut [AssignedCell<F, F>; 8],
        current_block_cells: [AssignedCell<F, F>; 16],
        processed_bytes_count: Value<F>,
        is_last_block: bool,
    ) -> Result<[AssignedCell<F, F>; 64], Error> {
        let mut state_vector: Vec<AssignedCell<F, F>> = Vec::new();
        state_vector.extend_from_slice(global_state);
        state_vector.extend_from_slice(iv_constants);

        let mut state: [AssignedCell<F, F>; 16] = state_vector.try_into().unwrap();

        // accumulative_state[12] ^= processed_bytes_count
        let processed_bytes_count_cell =
            self.new_row_from_value(processed_bytes_count, region, row_offset)?;
        state[12] = self.xor(&state[12], &processed_bytes_count_cell, region, row_offset);
        // accumulative_state[13] ^= ctx.processed_bytes_count[1]; This is 0 so we ignore it

        if is_last_block {
            state[14] = self.not(&state[14], region, row_offset);
        }

        for i in 0..12 {
            for j in 0..8 {
                self.mix(
                    Self::ABCD[j][0],
                    Self::ABCD[j][1],
                    Self::ABCD[j][2],
                    Self::ABCD[j][3],
                    Self::SIGMA[i][2 * j],
                    Self::SIGMA[i][2 * j + 1],
                    &mut state,
                    &current_block_cells,
                    region,
                    row_offset,
                )?;
            }
        }

        let mut global_state_bytes = Vec::new();
        for i in 0..8 {
            global_state[i] = self.xor(&global_state[i], &state[i], region, row_offset);
            let row = self.xor_with_full_rows(&global_state[i], &state[i + 8], region, row_offset);
            global_state_bytes.extend_from_slice(&row[1..]);
            global_state[i] = row[0].clone();
        }
        let global_state_bytes_array = global_state_bytes.try_into().unwrap();
        Ok(global_state_bytes_array)
    }

    #[allow(clippy::too_many_arguments)]
    fn mix(
        &mut self,
        a_: usize,
        b_: usize,
        c_: usize,
        d_: usize,
        sigma_even: usize,
        sigma_odd: usize,
        state: &mut [AssignedCell<F, F>; 16],
        current_block_words: &[AssignedCell<F, F>; 16],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let v_a = state[a_].clone();
        let v_b = state[b_].clone();
        let v_c = state[c_].clone();
        let v_d = state[d_].clone();
        let x = current_block_words[sigma_even].clone();
        let y = current_block_words[sigma_odd].clone();

        // v[a] = ((v[a] as u128 + v[b] as u128 + x as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add(&v_a, &v_b, region, offset);
        let a = self.add_copying_one_parameter(&a_plus_b, &x, region, offset);

        // v[d] = rotr_64(v[d] ^ v[a], 32);
        let d_xor_a = self.xor_for_mix(&a, &v_d, region, offset);
        let d = self.rotate_right_32(d_xor_a, region, offset);

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add_copying_one_parameter(&d, &v_c, region, offset);

        // v[b] = rotr_64(v[b] ^ v[c], 24);
        let b_xor_c = self.xor_for_mix(&c, &v_b, region, offset);
        let b = self.rotate_right_24(b_xor_c, region, offset);

        // v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add_copying_one_parameter(&b, &a, region, offset);
        let a = self.add_copying_one_parameter(&a_plus_b, &y, region, offset);

        // v[d] = rotr_64(v[d] ^ v[a], 16);
        let d_xor_a = self.xor_for_mix(&a, &d, region, offset);
        let d = self.rotate_right_16(d_xor_a, region, offset);

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add_copying_one_parameter(&d, &c, region, offset);

        // v[b] = rotr_64(v[b] ^ v[c], 63);
        let b_xor_c = self.xor_for_mix(&c, &b, region, offset);
        let b = self.rotate_right_63(b_xor_c, region, offset);

        state[a_] = a;
        state[b_] = b;
        state[c_] = c;
        state[d_] = d;

        Ok(())
    }

    fn block_words_from_bytes(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        block: [Value<F>; 128],
    ) -> Result<[Vec<AssignedCell<F, F>>; 16], Error> {
        let mut current_block_rows: Vec<Vec<AssignedCell<F, F>>> = Vec::new();
        for i in 0..16 {
            let bytes: [Value<F>; 8] = block[i * 8..(i + 1) * 8].try_into().unwrap();
            let current_row_cells = self.new_row_from_bytes(bytes, region, offset)?;
            current_block_rows.push(current_row_cells);
        }
        let current_block_words = current_block_rows.try_into().unwrap();
        Ok(current_block_words)
    }

    fn compute_processed_bytes_count_value_for_iteration(
        iteration: usize,
        is_last_block: bool,
        input_size: usize,
        empty_key: bool,
    ) -> Value<F> {
        let processed_bytes_count = if is_last_block {
            input_size + if empty_key { 0 } else { 128 }
        } else {
            128 * (iteration + 1)
        };

        Value::known(F::from(processed_bytes_count as u64))
    }

    // Create rows

    fn new_row_from_bytes(
        &mut self,
        bytes: [Value<F>; 8],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let ret = self.decompose_8_chip.generate_row_from_bytes(region, bytes, *offset);
        *offset += 1;
        ret
    }

    fn new_row_from_value(
        &mut self,
        value: Value<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let ret = self.decompose_8_chip.generate_row_from_value(region, value, *offset);
        *offset += 1;
        ret
    }

    // Copy constrains
    /// This method constrains the padding cells to equal zero. The amount of constraints
    /// depends on the input size and the key size, which makes sense since those values are known
    /// at circuit building time.
    /// The idea is that since we decompose the state into 8 limbs, we already have the input
    /// bytes in the trace. It's just a matter of iterating the cells in the correct order and knowing
    /// which ones should equal zero. In Blake2b the padding is allways 0.
    fn constrain_padding_cells_to_equal_zero(
        &mut self,
        region: &mut Region<F>,
        zeros_amount: usize,
        current_block_rows: &[Vec<AssignedCell<F, F>>; 16],
        zero_constant_cell: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        let mut constrained_padding_cells = 0;
        for row in (0..16).rev() {
            for limb in (1..9).rev() {
                if constrained_padding_cells < zeros_amount {
                    region.constrain_equal(
                        current_block_rows[row][limb].cell(),
                        zero_constant_cell.cell(),
                    )?;
                    constrained_padding_cells += 1;
                }
            }
        }
        Ok(())
    }

    /// Here we want to make sure that the public inputs are equal to the final state of the hash.
    /// The amount of constrains is equal to the output size, which is known at circuit building time.
    /// We should only constrain those, even tho the state contains the entire output.
    fn constraint_public_inputs_to_equal_computation_results(
        &self,
        layouter: &mut impl Layouter<F>,
        global_state_bytes: [AssignedCell<F, F>; 64],
        output_size: usize,
    ) -> Result<(), Error> {
        for (i, global_state_byte_cell) in global_state_bytes.iter().enumerate().take(output_size) {
            layouter.constrain_instance(
                global_state_byte_cell.cell(),
                self.expected_final_state,
                i,
            )?;
        }
        Ok(())
    }

    /// Set copy constraints to the part of the state that is copied from iv constants.
    fn constrain_initial_state(
        region: &mut Region<F>,
        global_state: &[AssignedCell<F, F>; 8],
        iv_constants: &[AssignedCell<F, F>; 8],
    ) -> Result<(), Error> {
        for i in 0..8 {
            region.constrain_equal(iv_constants[i].cell(), global_state[i].cell())?;
        }
        Ok(())
    }

    /// Assign constants to fixed cells to use later on
    fn assign_constant_to_fixed_cell(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        constant: usize,
        region_name: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        let constant_value = value_for(constant as u64);
        let ret = region.assign_fixed(|| region_name, self.constants, *offset, || constant_value);
        *offset += 1;
        ret
    }

    fn assign_01010000_constant_to_fixed_cell(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.assign_constant_to_fixed_cell(region, offset, 0x01010000, "state 0 xor")
    }

    fn assign_0_constant_to_fixed_cell(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.assign_constant_to_fixed_cell(region, offset, 0usize, "fixed 0")
    }

    /// Blake2b uses an initialization vector (iv) that is hardcoded. This method assigns those
    /// values to fixed cells to use later on.
    fn assign_iv_constants_to_fixed_cells(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> [AssignedCell<F, F>; 8] {
        let ret = Self::iv_constants()
            .iter()
            .map(|value| {
                let result = region
                    .assign_fixed(|| "iv constants", self.constants, *offset, || *value)
                    .unwrap();
                *offset += 1;
                result
            })
            .collect::<Vec<AssignedCell<F, F>>>()
            .try_into()
            .unwrap();
        ret
    }

    // Populate tables

    fn _populate_lookup_table_8(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
    }

    /// These are the methods that call primitive operation chips
    fn add(
        &mut self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.addition_chip
            .generate_addition_rows_from_cells(region, offset, lhs, rhs, &mut self.decompose_8_chip)
            .unwrap()[0]
            .clone()
    }

    /// Sometimes we can reutilice an output row to be the input row of the next operation. This is
    /// a convenience method for that in the case of the sum operation.
    fn add_copying_one_parameter(
        &mut self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.addition_chip
            .generate_addition_rows_from_cells_optimized(
                region,
                offset,
                previous_cell,
                cell_to_copy,
                &mut self.decompose_8_chip,
            )
            .unwrap()[0]
            .clone()
    }

    fn not(
        &mut self,
        input_cell: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.negate_chip
            .generate_rows_from_cell(region, offset, input_cell, &mut self.decompose_8_chip)
            .unwrap()
    }

    fn xor(
        &mut self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.xor_chip
            .generate_xor_rows_from_cells_optimized(
                region,
                offset,
                lhs,
                rhs,
                &mut self.decompose_8_chip,
                false,
            )
            .unwrap()[0]
            .clone()
    }

    /// Sometimes we can reutilice an output row to be the input row of the next operation. This is
    /// a convenience method for that in the case of the xor operation.
    fn xor_for_mix(
        &mut self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> [AssignedCell<F, F>; 9] {
        self.xor_copying_one_parameter(previous_cell, cell_to_copy, region, offset)
    }

    fn xor_copying_one_parameter(
        &mut self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> [AssignedCell<F, F>; 9] {
        self.xor_chip
            .generate_xor_rows_from_cells_optimized(
                region,
                offset,
                previous_cell,
                cell_to_copy,
                &mut self.decompose_8_chip,
                true,
            )
            .unwrap()
    }

    /// In this case we need to perform the xor operation and return the entire row, because we
    /// need it to constrain the result.
    fn xor_with_full_rows(
        &mut self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> [AssignedCell<F, F>; 9] {
        self.xor_chip
            .generate_xor_rows_from_cells_optimized(
                region,
                offset,
                lhs,
                rhs,
                &mut self.decompose_8_chip,
                false,
            )
            .unwrap()
    }

    fn rotate_right_63(
        &mut self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.rotate_63_chip
            .generate_rotation_rows_from_cells(
                region,
                offset,
                input_row,
                &mut self.decompose_8_chip,
            )
            .unwrap()
    }

    fn rotate_right_16(
        &mut self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_input_row(
                region,
                offset,
                &mut self.decompose_8_chip,
                input_row,
                2,
            )
            .unwrap()
    }

    fn rotate_right_24(
        &mut self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_input_row(
                region,
                offset,
                &mut self.decompose_8_chip,
                input_row,
                3,
            )
            .unwrap()
    }

    fn rotate_right_32(
        &mut self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_input_row(
                region,
                offset,
                &mut self.decompose_8_chip,
                input_row,
                4,
            )
            .unwrap()
    }

    /// Constants for Blake2b
    const ABCD: [[usize; 4]; 8] = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];

    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];

    fn iv_constants() -> [Value<F>; 8] {
        [
            value_for(0x6A09E667F3BCC908u128),
            value_for(0xBB67AE8584CAA73Bu128),
            value_for(0x3C6EF372FE94F82Bu128),
            value_for(0xA54FF53A5F1D36F1u128),
            value_for(0x510E527FADE682D1u128),
            value_for(0x9B05688C2B3E6C1Fu128),
            value_for(0x1F83D9ABFB41BD6Bu128),
            value_for(0x5BE0CD19137E2179u128),
        ]
    }
}
