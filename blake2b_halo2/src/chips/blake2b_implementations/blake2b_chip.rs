use super::*;
use crate::auxiliar_functions::{value_for};
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::decompose_16_chip::Decompose16Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::decomposition_trait::Decomposition;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::negate_chip::NegateChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed, Instance};

cfg_if::cfg_if! {
    if #[cfg(feature = "sum_with_8_limbs")] {
        type AdditionChip<F> = AdditionMod64Chip<F, 8, 10>;
    } else if #[cfg(feature = "sum_with_4_limbs")] {
        type AdditionChip<F> = AdditionMod64Chip<F, 4, 6>;
    } else {
        panic!("No feature selected");
    }
}

const BLAKE2B_BLOCK_SIZE: usize = 128;

#[derive(Clone, Debug)]
pub struct Blake2bChip<F: PrimeField> {
    addition_chip: AdditionChip<F>,
    decompose_16_chip: Decompose16Chip<F>,

    decompose_8_chip: Decompose8Chip<F>,
    generic_limb_rotation_chip: LimbRotationChip<F>,
    rotate_63_chip: Rotate63Chip<F, 8, 9>,
    xor_chip: XorChip<F>,
    negate_chip: NegateChip<F>,

    constants: Column<Fixed>,
    expected_final_state: Column<Instance>,
}

impl<F: PrimeField> Blake2bChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(feature = "sum_with_8_limbs")] {
                let carry = meta.advice_column();
                let addition_chip = AdditionMod64Chip::<F, 8, 10>::configure(meta, full_number_u64, carry);
            } else if #[cfg(feature = "sum_with_4_limbs")] {
                let addition_chip = AdditionMod64Chip::<F, 4, 6>::configure(meta, full_number_u64, limbs[4]);
            } else {
                panic!("No feature selected");
            }
        }

        let decompose_16_chip =
            Decompose16Chip::configure(meta, full_number_u64, limbs[0..4].try_into().unwrap());
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
            decompose_16_chip,
            generic_limb_rotation_chip,
            rotate_63_chip,
            xor_chip,
            negate_chip,
            constants,
            expected_final_state,
        }
    }

    pub fn initialize_with(&mut self, layouter: &mut impl Layouter<F>) {
        self._populate_lookup_table_8(layouter);
        self._populate_xor_lookup_table(layouter);
        cfg_if::cfg_if! {
            if #[cfg(feature = "sum_with_4_limbs")] {
                self._populate_lookup_table_16(layouter);
            }
        }
    }

    pub fn compute_blake2b_hash_for_inputs(
        &mut self,
        layouter: &mut impl Layouter<F>,
        output_size: usize,
        input_size: usize,
        key_size: usize,
        input: &Vec<Value<F>>,
        key: &Vec<Value<F>>,
    ) -> Result<(), Error> {

        assert!(output_size <= 64, "Output size must be between 1 and 64 bytes");

        let iv_constants: [AssignedCell<F, F>; 8] =
            self.assign_iv_constants_to_fixed_cells(layouter);
        let init_const_state_0 = self.assign_01010000_constant_to_fixed_cell(layouter)?;
        let output_size_constant =
            self.assign_constant_to_fixed_cell(layouter, output_size, "output size")?;
        let key_size_constant_shifted =
            self.assign_constant_to_fixed_cell(layouter, key_size << 8, "key size")?;
        let mut global_state = self.compute_initial_state(
            layouter,
            &iv_constants,
            init_const_state_0,
            output_size_constant,
            key_size_constant_shifted,
        )?;

        let global_state_bytes = self.perform_blake2b_iterations(
            layouter,
            input_size,
            input,
            key,
            &iv_constants,
            &mut global_state,
        )?;

        self.constraint_public_inputs_to_equal_computation_results(
            layouter,
            global_state_bytes,
            output_size,
        )
    }

    // ================ PRIVATE METHODS ================

    // Core methods

    fn compute_initial_state(
        &mut self,
        layouter: &mut impl Layouter<F>,
        iv_constants: &[AssignedCell<F, F>; 8],
        init_const_state_0: AssignedCell<F, F>,
        output_size_constant: AssignedCell<F, F>,
        key_size_constant_shifted: AssignedCell<F, F>,
    ) -> Result<[AssignedCell<F, F>; 8], Error> {
        let mut global_state = Self::iv_constants()
            .map(|constant| self.new_row_from_value(constant, layouter).unwrap());

        Self::constrain_initial_state(layouter, &mut global_state, iv_constants)?;

        // state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        global_state[0] = self.xor(global_state[0].clone(), init_const_state_0.clone(), layouter);
        global_state[0] = self.xor(global_state[0].clone(), output_size_constant, layouter);
        global_state[0] = self.xor(global_state[0].clone(), key_size_constant_shifted, layouter);
        Ok(global_state)
    }

    fn perform_blake2b_iterations(
        &mut self,
        layouter: &mut impl Layouter<F>,
        input_size: usize,
        input: &Vec<Value<F>>,
        key: &Vec<Value<F>>,
        iv_constants: &[AssignedCell<F, F>; 8],
        global_state: &mut [AssignedCell<F, F>; 8],
    ) -> Result<[AssignedCell<F, F>; 64], Error> {
        // This is just to be able to return the result of the last compress call
        let mut global_state_bytes = Err(Error::Synthesis);

        let is_key_empty = key.is_empty();
        let is_input_empty = input_size == 0;

        let input_blocks = input_size.div_ceil(BLAKE2B_BLOCK_SIZE);
        let total_blocks = Self::get_total_blocks_count(
            input_blocks, is_input_empty, is_key_empty
        );
        let last_input_block_index = if is_input_empty { 0 } else { input_blocks - 1 };

        for i in 0..total_blocks {
            let is_last_block = i == total_blocks - 1;
            let is_key_block = !is_key_empty && i == 0;

            let processed_bytes_count = Self::compute_processed_bytes_count_value_for_iteration(
                i,
                is_last_block,
                input_size,
                is_key_empty,
            );

            let current_block_rows = self.build_current_block_rows(
                layouter, input, key, i, last_input_block_index, is_key_empty, is_last_block, is_key_block
            )?;

            if is_last_block {
                let zeros_amount_for_input_padding = if input_size == 0 {
                    128
                } else {
                    (BLAKE2B_BLOCK_SIZE - input_size % BLAKE2B_BLOCK_SIZE) % BLAKE2B_BLOCK_SIZE
                };
                self.constrain_padding_cells_to_equal_zero(
                    layouter,
                    zeros_amount_for_input_padding,
                    &current_block_rows,
                )?;
            }

            if is_key_block {
                let zeros_amount_for_key_padding = BLAKE2B_BLOCK_SIZE - key.len();
                self.constrain_padding_cells_to_equal_zero(
                    layouter,
                    zeros_amount_for_key_padding,
                    &current_block_rows,
                )?;
            }

            let current_block_cells = Self::get_full_number_of_each(current_block_rows);

            let result = self.compress(
                layouter,
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

    fn get_total_blocks_count(input_blocks: usize, is_input_empty: bool, is_key_empty: bool) -> usize {
        if is_key_empty {
            if is_input_empty {
                1
            } else {
                input_blocks
            }
        } else if is_input_empty {
            1
        } else {
            input_blocks + 1
        }
    }

    fn build_current_block_rows(&mut self, layouter: &mut impl Layouter<F>, input: &Vec<Value<F>>, key: &Vec<Value<F>>, block_number: usize, last_input_block_index: usize, is_key_empty: bool, is_last_block: bool, is_key_block: bool) -> Result<[Vec<AssignedCell<F, F>>; 16], Error> {
        let current_block_values = Self::build_values_for_current_block(
            input, key, block_number, last_input_block_index, is_key_empty, is_last_block, is_key_block
        );

        let current_block_rows =
            self.block_words_from_bytes(layouter, current_block_values.try_into().unwrap())?;
        Ok(current_block_rows)
    }

    fn build_values_for_current_block(input: &Vec<Value<F>>, key: &Vec<Value<F>>, block_number: usize, last_input_block_index: usize, is_key_empty: bool, is_last_block: bool, is_key_block: bool) -> Vec<Value<F>> {
        let current_block_values: Vec<Value<F>> = if is_last_block && !is_key_block {
            let mut result =
                input[last_input_block_index * BLAKE2B_BLOCK_SIZE..].to_vec();
            result.resize(128, Value::known(F::ZERO));
            result
        } else if is_key_block {
            let mut result = key.to_vec();
            result.resize(128, Value::known(F::ZERO));
            result
        } else {
            let current_input_block_index = if is_key_empty { block_number } else { block_number - 1 };
            let result = input[current_input_block_index * BLAKE2B_BLOCK_SIZE
                ..(current_input_block_index + 1) * BLAKE2B_BLOCK_SIZE]
                .to_vec();
            result
        };
        current_block_values
    }

    fn get_full_number_of_each(
        current_block_rows: [Vec<AssignedCell<F, F>>; 16],
    ) -> [AssignedCell<F, F>; 16] {
        current_block_rows.iter().map(|row| row[0].clone()).collect::<Vec<_>>().try_into().unwrap()
    }

    fn compress(
        &mut self,
        layouter: &mut impl Layouter<F>,
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
            self.new_row_from_value(processed_bytes_count, layouter)?;
        state[12] = self.xor(state[12].clone(), processed_bytes_count_cell.clone(), layouter);
        // accumulative_state[13] ^= ctx.processed_bytes_count[1]; This is 0 so we ignore it

        if is_last_block {
            state[14] = self.not(state[14].clone(), layouter);
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
                    layouter,
                )?;
            }
        }

        let mut global_state_bytes = Vec::new();
        for i in 0..8 {
            global_state[i] = self.xor(global_state[i].clone(), state[i].clone(), layouter);
            let row =
                self.xor_with_full_rows(global_state[i].clone(), state[i + 8].clone(), layouter);
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
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let v_a = state[a_].clone();
        let v_b = state[b_].clone();
        let v_c = state[c_].clone();
        let v_d = state[d_].clone();
        let x = current_block_words[sigma_even].clone();
        let y = current_block_words[sigma_odd].clone();

        // v[a] = ((v[a] as u128 + v[b] as u128 + x as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add(v_a, v_b.clone(), layouter);
        let a = self.add(a_plus_b, x, layouter);

        // v[d] = rotr_64(v[d] ^ v[a], 32);
        let d_xor_a = self.xor(v_d.clone(), a.clone(), layouter);
        let d = self.rotate_right_32(d_xor_a, layouter);

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add(v_c, d.clone(), layouter);

        // v[b] = rotr_64(v[b] ^ v[c], 24);
        let b_xor_c = self.xor(v_b, c.clone(), layouter);
        let b = self.rotate_right_24(b_xor_c, layouter);

        // v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add(a.clone(), b.clone(), layouter);
        let a = self.add(a_plus_b, y, layouter);

        // v[d] = rotr_64(v[d] ^ v[a], 16);
        let d_xor_a = self.xor(d.clone(), a.clone(), layouter);
        let d = self.rotate_right_16(d_xor_a, layouter);

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add(c.clone(), d.clone(), layouter);

        // v[b] = rotr_64(v[b] ^ v[c], 63);
        let b_xor_c = self.xor(b.clone(), c.clone(), layouter);
        let b = self.rotate_right_63(b_xor_c, layouter);

        state[a_] = a;
        state[b_] = b;
        state[c_] = c;
        state[d_] = d;

        Ok(())
    }

    fn block_words_from_bytes(
        &mut self,
        layouter: &mut impl Layouter<F>,
        block: [Value<F>; 128],
    ) -> Result<[Vec<AssignedCell<F, F>>; 16], Error> {
        let mut current_block_rows: Vec<Vec<AssignedCell<F, F>>> = Vec::new();
        for i in 0..16 {
            let bytes: [Value<F>; 8] = block[i * 8..(i + 1) * 8].try_into().unwrap();
            let current_row_cells = self.new_row_from_bytes(bytes, layouter)?;
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
        layouter: &mut impl Layouter<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        layouter.assign_region(
            || "row",
            |mut region| self.decompose_8_chip.generate_row_from_bytes(&mut region, bytes, 0),
        )
    }

    fn new_row_from_value(
        &mut self,
        value: Value<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "row",
            |mut region| self.decompose_8_chip.generate_row_from_value(&mut region, value, 0),
        )
    }

    // Copy constrains

    fn constrain_padding_cells_to_equal_zero(
        &mut self,
        layouter: &mut impl Layouter<F>,
        zeros_amount: usize,
        current_block_rows: &[Vec<AssignedCell<F, F>>; 16],
    ) -> Result<(), Error> {
        let zero_constant_cell = self.assign_0_constant_to_fixed_cell(layouter)?;
        let mut constrained_padding_cells = 0;
        layouter.assign_region(
            || "constrain padding",
            |mut region| {
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
            },
        )?;

        Ok(())
    }

    fn constraint_public_inputs_to_equal_computation_results(
        &self,
        layouter: &mut impl Layouter<F>,
        global_state_bytes: [AssignedCell<F, F>; 64],
        output_size: usize,
    ) -> Result<(), Error> {
        for i in 0..output_size {
            layouter.constrain_instance(
                global_state_bytes[i].cell(),
                self.expected_final_state,
                i,
            )?;
        }
        Ok(())
    }

    fn constrain_initial_state(
        layouter: &mut impl Layouter<F>,
        global_state: &mut [AssignedCell<F, F>; 8],
        iv_constants: &[AssignedCell<F, F>; 8],
    ) -> Result<(), Error> {
        // Set copy constraints to recently initialized state
        layouter.assign_region(
            || "iv copy constraints",
            |mut region| {
                for i in 0..8 {
                    region.constrain_equal(iv_constants[i].cell(), global_state[i].cell())?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    // Assign constants

    fn assign_constant_to_fixed_cell(
        &self,
        layouter: &mut impl Layouter<F>,
        constant: usize,
        region_name: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        let constant_value = Value::known(F::from(constant as u64));
        layouter.assign_region(
            || region_name,
            |mut region| region.assign_fixed(|| region_name, self.constants, 0, || constant_value),
        )
    }

    fn assign_01010000_constant_to_fixed_cell(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "constant",
            |mut region| {
                region.assign_fixed(
                    || "state 0 xor",
                    self.constants,
                    0,
                    || value_for(0x01010000u64),
                )
            },
        )
    }

    fn assign_0_constant_to_fixed_cell(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "constant",
            |mut region| region.assign_fixed(|| "fixed 0", self.constants, 0, || value_for(0u64)),
        )
    }

    fn assign_iv_constants_to_fixed_cells(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> [AssignedCell<F, F>; 8] {
        Self::iv_constants()
            .iter()
            .enumerate()
            .map(|(i, value)| {
                layouter
                    .assign_region(
                        || "row",
                        |mut region| {
                            region.assign_fixed(|| "iv constants", self.constants, i, || *value)
                        },
                    )
                    .unwrap()
            })
            .collect::<Vec<AssignedCell<F, F>>>()
            .try_into()
            .unwrap()
    }

    // Populate tables

    fn _populate_lookup_table_8(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    #[allow(dead_code)]
    fn _populate_lookup_table_16(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_16_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
    }

    // Primitive operations (they are public for testing purposes)

    fn add(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "sum_with_8_limbs")] {
                self.addition_chip
                    .generate_addition_rows_from_cells(layouter, lhs, rhs, &mut self.decompose_8_chip)
                    .unwrap()
            } else if #[cfg(feature = "sum_with_4_limbs")] {
                self.addition_chip
                    .generate_addition_rows_from_cells(layouter, lhs, rhs, &mut self.decompose_16_chip)
                    .unwrap()
            } else {
                panic!("No feature selected");
            }
        }
    }

    fn not(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.negate_chip
            .generate_rows_from_cell(layouter, input_cell, &mut self.decompose_8_chip)
            .unwrap()
    }

    fn xor(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.xor_chip
            .generate_xor_rows_from_cells(layouter, lhs, rhs, &mut self.decompose_8_chip)
            .unwrap()[0]
            .clone()
    }

    fn xor_with_full_rows(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> [AssignedCell<F, F>; 9] {
        self.xor_chip
            .generate_xor_rows_from_cells(layouter, lhs, rhs, &mut self.decompose_8_chip)
            .unwrap()
    }

    fn rotate_right_63(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.rotate_63_chip
            .generate_rotation_rows_from_cells(layouter, input_cell, &mut self.decompose_8_chip)
            .unwrap()
    }

    fn rotate_right_16(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 2)
            .unwrap()
    }

    fn rotate_right_24(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 3)
            .unwrap()
    }

    fn rotate_right_32(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 4)
            .unwrap()
    }

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
