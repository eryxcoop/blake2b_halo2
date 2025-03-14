use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance};
use crate::auxiliar_functions::value_for;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::decomposition::Decomposition;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::base_operations::xor::Xor;
use crate::blake2b::chips::utils::{compute_processed_bytes_count_value_for_iteration, constrain_initial_state, enforce_input_sizes, enforce_modulus_size, get_full_number_of_each, get_total_blocks_count, iv_constants, ABCD, BLAKE2B_BLOCK_SIZE, SIGMA};

/// This is the trait that groups the 3 optimization chips. Most of their code is the same, so the
/// behaviour was encapsulated here. Each optimization has to override only 3 or 4 methods, besides
/// its signature for some of the gates.
pub trait Blake2bGeneric: Clone {

    /// Configuration of the circuit, this includes initialization of all the necessary configs.
    /// Some of them are general for every implementation, some are optimization-specific.
    /// It should be called in the configuration of the user circuit.
    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self;

    // [Inigo comment] Strange name - initialise with what? Also, this seems something non blake2b-specific
    /// Initialization of the circuit. This will usually create the needed lookup tables for the
    /// specific optimization. This should be called on the synthesize of the circuit but only once.
    fn initialize_with<F: PrimeField>(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    // Getters for the internal members of the chip
    fn decompose_8_config(&self) -> Decompose8Config;
    fn generic_limb_rotation_config(&self) -> LimbRotation;
    fn rotate_63_config(&self) -> Rotate63Config<8, 9>;
    fn xor_config(&self) -> impl Xor;
    fn negate_config(&self) -> NegateConfig;
    fn constants(&self) -> Column<Fixed>;
    fn expected_final_state(&self) -> Column<Instance>;

    // ---------- MAIN METHODS ---------- //

    /// This is the main method of the chips. It computes the Blake2b hash for the given inputs.
    fn compute_blake2b_hash_for_inputs<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        output_size: usize,
        input_size: usize,
        key_size: usize,
        input: &[Value<F>],
        key: &[Value<F>],
    ) -> Result<(), Error> {
        enforce_input_sizes(output_size, key_size);

        /// All the computation is performed inside a single region. Some optimizations take advantage
        /// of this fact, since we want to avoid copying cells between regions.
        let global_state_bytes = layouter.assign_region(
            || "single region",
            |mut region| {
                /// Initialize in 0 the offset for the fixed cells in the region
                let mut constants_offset: usize = 0;
                let iv_constant_cells: [AssignedCell<F, F>; 8] =
                    self.assign_iv_constants_to_fixed_cells(&mut region, &mut constants_offset);
                let init_const_state_0 = self.assign_constant_to_fixed_cell(&mut region, &mut constants_offset, 0x01010000, "state 0 xor")?;
                let output_size_constant = self.assign_constant_to_fixed_cell(&mut region, &mut constants_offset, output_size, "output size")?;
                let key_size_constant_shifted = self.assign_constant_to_fixed_cell(&mut region, &mut constants_offset, key_size << 8, "key size")?;

                /// Initialize in 0 the offset for the advice cells in the region
                let mut advice_offset: usize = 0;

                let mut global_state = self.compute_initial_state(
                    &mut region,
                    &mut advice_offset,
                    &iv_constant_cells,
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
                    &iv_constant_cells,
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

    /// This method handles the part of the configuration that is generic to all optimizations.
    /// Most of the operations are performed the same way in all optimizations.
    fn generic_configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> (
        Decompose8Config,
        LimbRotation,
        Rotate63Config<8, 9>,
        NegateConfig,
        Column<Fixed>,
        Column<Instance>,
    ) {
        enforce_modulus_size::<F>();
        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);
        let rotate_63_config = Rotate63Config::configure(meta, full_number_u64);
        let negate_config = NegateConfig::configure(meta, full_number_u64);

        let constants = meta.fixed_column();
        meta.enable_equality(constants);

        let expected_final_state = meta.instance_column();
        meta.enable_equality(expected_final_state);

        (
            decompose_8_config,
            LimbRotation,
            rotate_63_config,
            negate_config,
            constants,
            expected_final_state,
        )
    }

    /// This method handles the part of the initialization of the chip that is generic to all
    /// optimizations. In particular, the initialization of lookup tables.
    fn generic_initialize_with<F: PrimeField>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.populate_lookup_table_8(layouter)?;
        self.populate_xor_lookup_table(layouter)?;
        Ok(())
    }

    /// Computes the initial global state of Blake2b. It only depends on the key size and the
    /// output size, which are values known at circuit building time. This computation should
    /// also be verified by the circuit.
    fn compute_initial_state<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        iv_constant_cells: &[AssignedCell<F, F>; 8],
        init_const_state_0: AssignedCell<F, F>,
        output_size_constant: AssignedCell<F, F>,
        key_size_constant_shifted: AssignedCell<F, F>,
    ) -> Result<[AssignedCell<F, F>; 8], Error> {
        let mut global_state = iv_constants()
            .map(|constant| self.new_row_from_value(constant, region, offset).unwrap());

        constrain_initial_state(region, &global_state, iv_constant_cells)?;

        // state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        global_state[0] = self.xor(&global_state[0], &init_const_state_0, region, offset)?;
        global_state[0] = self.xor(&global_state[0], &output_size_constant, region, offset)?;
        global_state[0] = self.xor(&global_state[0], &key_size_constant_shifted, region, offset)?;
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
        let total_blocks = get_total_blocks_count(input_blocks, is_input_empty, is_key_empty);
        let last_input_block_index = if is_input_empty { 0 } else { input_blocks - 1 };

        /// Main loop
        for i in 0..total_blocks {
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
                self.assign_constant_to_fixed_cell(region, constants_offset, 0usize, "fixed 0")?;

            /// Padding for the last block, in case the key block is not the only one.
            if is_last_block && !is_key_block {
                let zeros_amount_for_input_padding = if input_size == 0 {
                    128
                } else {
                    // Complete the block with zeroes
                    (BLAKE2B_BLOCK_SIZE - input_size % BLAKE2B_BLOCK_SIZE)
                        % BLAKE2B_BLOCK_SIZE
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

            let current_block_cells = get_full_number_of_each(current_block_rows);

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

    /// This method computes a compression round of Blake2b. If the algorithm is in its last round,
    /// the is_last_block parameter should be set to true.
    #[allow(clippy::too_many_arguments)]
    fn compress<F: PrimeField>(
        &self,
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
        state[12] = self.xor(&state[12], &processed_bytes_count_cell, region, row_offset)?;
        // accumulative_state[13] ^= ctx.processed_bytes_count[1]; This is 0 so we ignore it

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

        let mut global_state_bytes = Vec::new();
        for i in 0..8 {
            global_state[i] = self.xor(&global_state[i], &state[i], region, row_offset)?;
            let row =
                self.xor_with_full_rows(&global_state[i], &state[i + 8], region, row_offset)?;
            global_state_bytes.extend_from_slice(&row[1..]);
            global_state[i] = row[0].clone();
        }
        let global_state_bytes_array = global_state_bytes.try_into().unwrap();
        Ok(global_state_bytes_array)
    }

    /// This method computes a single round of mixing for the Blake2b algorithm.
    /// One round of compress has 96 mixing rounds
    #[allow(clippy::too_many_arguments)]
    fn mix<F: PrimeField>(
        &self,
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
        let a_plus_b = self.add(&v_a, &v_b, region, offset)?;
        let a = self.add_copying_one_parameter(&a_plus_b, &x, region, offset)?;

        // v[d] = rotr_64(v[d] ^ v[a], 32);
        let d_xor_a = self.xor_for_mix(&a, &v_d, region, offset)?;
        let d = self.rotate_right_32(d_xor_a, region, offset)?;

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add_copying_one_parameter(&d, &v_c, region, offset)?;

        // v[b] = rotr_64(v[b] ^ v[c], 24);
        let b_xor_c = self.xor_for_mix(&c, &v_b, region, offset)?;
        let b = self.rotate_right_24(b_xor_c, region, offset)?;

        // v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add_copying_one_parameter(&b, &a, region, offset)?;
        let a = self.add_copying_one_parameter(&a_plus_b, &y, region, offset)?;

        // v[d] = rotr_64(v[d] ^ v[a], 16);
        let d_xor_a = self.xor_for_mix(&a, &d, region, offset)?;
        let d = self.rotate_right_16(d_xor_a, region, offset)?;

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add_copying_one_parameter(&d, &c, region, offset)?;

        // v[b] = rotr_64(v[b] ^ v[c], 63);
        let b_xor_c = self.xor_for_mix(&c, &b, region, offset)?;
        let b = self.rotate_right_63(b_xor_c, region, offset)?;

        state[a_] = a;
        state[b_] = b;
        state[c_] = c;
        state[d_] = d;

        Ok(())
    }

    // ----- Basic operations ----- //

    /// In this case we need to perform the xor operation and return the entire row, because we
    /// need it to constrain the result.
    fn xor_with_full_rows<F: PrimeField>(
        &self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedCell<F, F>; 9], Error> {
        let decompose_8_config = self.decompose_8_config();
        self.xor_config().generate_xor_rows_from_cells(
            region,
            offset,
            lhs,
            rhs,
            &decompose_8_config,
            false,
        )
    }

    fn not<F: PrimeField>(
        &self,
        input_cell: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        self.negate_config().generate_rows_from_cell(
            region,
            offset,
            input_cell,
            &mut decompose_8_config,
        )
    }

    fn xor<F: PrimeField>(
        &self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let decompose_8_config = self.decompose_8_config();
        let full_number_cell = self.xor_config().generate_xor_rows_from_cells(
            region,
            offset,
            lhs,
            rhs,
            &decompose_8_config,
            false,
        )?[0]
            .clone();
        Ok(full_number_cell)
    }

    fn add<F: PrimeField>(
        &self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error>;

    /// Sometimes we can reutilice an output row to be the input row of the next operation. This is
    /// a convenience method for that in the case of the sum operation.
    fn add_copying_one_parameter<F: PrimeField>(
        &self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error>;

    /// Sometimes we can reutilice an output row to be the input row of the next operation. This is
    /// a convenience method for that in the case of the xor operation.
    fn xor_for_mix<F: PrimeField>(
        &self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedCell<F, F>; 9], Error>;

    fn rotate_right_63<F: PrimeField>(
        &self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        self.rotate_63_config().generate_rotation_rows_from_cells(
            region,
            offset,
            input_row,
            &mut decompose_8_config,
        )
    }

    fn rotate_right_16<F: PrimeField>(
        &self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        self.generic_limb_rotation_config().generate_rotation_rows_from_input_row(
            region,
            offset,
            &mut decompose_8_config,
            input_row,
            2,
        )
    }

    fn rotate_right_24<F: PrimeField>(
        &self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        self.generic_limb_rotation_config().generate_rotation_rows_from_input_row(
            region,
            offset,
            &mut decompose_8_config,
            input_row,
            3,
        )
    }

    fn rotate_right_32<F: PrimeField>(
        &self,
        input_row: [AssignedCell<F, F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        self.generic_limb_rotation_config().generate_rotation_rows_from_input_row(
            region,
            offset,
            &mut decompose_8_config,
            input_row,
            4,
        )
    }

    // ----- Auxiliar methods ----- //

    fn populate_lookup_table_8<F: PrimeField>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.decompose_8_config().populate_lookup_table(layouter)
    }

    fn populate_xor_lookup_table<F: PrimeField>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.xor_config().populate_xor_lookup_table(layouter)
    }

    /// Blake2b uses an initialization vector (iv) that is hardcoded. This method assigns those
    /// values to fixed cells to use later on.
    fn assign_iv_constants_to_fixed_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> [AssignedCell<F, F>; 8] {
        let ret = iv_constants()
            .iter()
            .map(|value| {
                let result = region
                    .assign_fixed(|| "iv constants", self.constants(), *offset, || *value)
                    .unwrap();
                *offset += 1;
                result
            })
            .collect::<Vec<AssignedCell<F, F>>>()
            .try_into()
            .unwrap();
        ret
    }

    /// Assign constants to fixed cells to use later on
    fn assign_constant_to_fixed_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        constant: usize,
        region_name: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        let constant_value = value_for(constant as u64);
        let ret = region.assign_fixed(|| region_name, self.constants(), *offset, || constant_value);
        *offset += 1;
        ret
    }

    /// Creates a new row with a full number in the first columns and the 8 bit decomposition in
    /// the following cells. Returns only the AssignedCell with the full number.
    fn new_row_from_value<F: PrimeField>(
        &self,
        value: Value<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let ret = self.decompose_8_config().generate_row_from_value(region, value, *offset);
        *offset += 1;
        ret
    }

    /// This method constrains the padding cells to equal zero. The amount of constraints
    /// depends on the input size and the key size, which makes sense since those values are known
    /// at circuit building time.
    /// The idea is that since we decompose the state into 8 limbs, we already have the input
    /// bytes in the trace. It's just a matter of iterating the cells in the correct order and knowing
    /// which ones should equal zero. In Blake2b the padding is allways 0.
    fn constrain_padding_cells_to_equal_zero<F: PrimeField>(
        &self,
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

    #[allow(clippy::too_many_arguments)]
    fn build_current_block_rows<F: PrimeField>(
        &self,
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

    /// Computes the values of the current block in the blake2b algorithm, based on the input and
    /// the block number we're on.
    fn build_values_for_current_block<F: PrimeField>(
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

    fn block_words_from_bytes<F: PrimeField>(
        &self,
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

    /// Given an array of byte-values, it puts in the circuit a full row with those bytes in the
    /// limbs and the resulting full number in the first column.
    fn new_row_from_bytes<F: PrimeField>(
        &self,
        bytes: [Value<F>; 8],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let ret = self.decompose_8_config().generate_row_from_bytes(region, bytes, *offset);
        *offset += 1;
        ret
    }

    /// Here we want to make sure that the public inputs are equal to the final state of the hash.
    /// The amount of constrains is equal to the output size, which is known at circuit building time.
    /// We should only constrain those, even tho the state contains the entire output.
    fn constraint_public_inputs_to_equal_computation_results<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        global_state_bytes: [AssignedCell<F, F>; 64],
        output_size: usize,
    ) -> Result<(), Error> {
        for (i, global_state_byte_cell) in global_state_bytes.iter().enumerate().take(output_size) {
            layouter.constrain_instance(
                global_state_byte_cell.cell(),
                self.expected_final_state(),
                i,
            )?;
        }
        Ok(())
    }
}
