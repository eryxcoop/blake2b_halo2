use super::*;
use crate::auxiliar_functions::value_for;
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

#[derive(Clone, Debug)]
pub struct Blake2bTable16Chip<F: PrimeField> {
    addition_chip: AdditionMod64Chip<F, 4, 6>,
    decompose_8_chip: Decompose8Chip<F>,
    decompose_16_chip: Decompose16Chip<F>,
    generic_limb_rotation_chip: LimbRotationChip<F>,
    rotate_63_chip: Rotate63Chip<F, 8, 9>,
    xor_chip: XorChip<F>,
    negate_chip: NegateChip<F>,

    constants: Column<Fixed>,
    expected_final_state: Column<Instance>,
}

impl<F: PrimeField> Blake2bTable16Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);
        let decompose_16_chip =
            Decompose16Chip::configure(meta, full_number_u64, limbs[0..4].try_into().unwrap());
        let addition_chip =
            AdditionMod64Chip::<F, 4, 6>::configure(meta, full_number_u64, limbs[4]);
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
        self._populate_lookup_table_16(layouter);
        self._populate_xor_lookup_table(layouter);
    }

    pub fn add(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.addition_chip
            .generate_addition_rows_from_cells(layouter, lhs, rhs, &mut self.decompose_16_chip)
            .unwrap()
    }

    pub fn not(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.negate_chip
            .generate_rows_from_cell(layouter, input_cell, &mut self.decompose_8_chip)
            .unwrap()
    }

    pub fn xor(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.xor_chip
            .generate_xor_rows_from_cells(layouter, lhs, rhs, &mut self.decompose_8_chip)
            .unwrap()
    }

    pub fn rotate_right_63(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.rotate_63_chip
            .generate_rotation_rows_from_cells(layouter, input_cell, &mut self.decompose_8_chip)
            .unwrap()
    }

    pub fn rotate_right_16(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 2)
            .unwrap()
    }

    pub fn rotate_right_24(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 3)
            .unwrap()
    }

    pub fn rotate_right_32(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self.generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 4)
            .unwrap()
    }

    pub fn new_row_from_value(
        &mut self,
        value: Value<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "row",
            |mut region| {
                self.decompose_8_chip
                    .generate_row_from_value(&mut region, value, 0)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mix(
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
        // Self::assert_values_are_equal(a.clone(), value_for(13481588052017302553u64));

        // v[d] = rotr_64(v[d] ^ v[a], 32);
        let d_xor_a = self.xor(v_d.clone(), a.clone(), layouter);
        let d = self.rotate_right_32(d_xor_a, layouter);
        // Self::assert_values_are_equal(d.clone(), value_for(955553433272085144u64));

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add(v_c, d.clone(), layouter);
        // Self::assert_values_are_equal(c.clone(), value_for(8596445010228097952u64));

        // v[b] = rotr_64(v[b] ^ v[c], 24);
        let b_xor_c = self.xor(v_b, c.clone(), layouter);
        let b = self.rotate_right_24(b_xor_c, layouter);
        // Self::assert_values_are_equal(b.clone(), value_for(3868997964033118064u64));

        // v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
        let a_plus_b = self.add(a.clone(), b.clone(), layouter);
        let a = self.add(a_plus_b, y, layouter);
        // Self::assert_values_are_equal(a.clone(), value_for(13537687662323754138u64));

        // v[d] = rotr_64(v[d] ^ v[a], 16);
        let d_xor_a = self.xor(d.clone(), a.clone(), layouter);
        let d = self.rotate_right_16(d_xor_a, layouter);
        // Self::assert_values_are_equal(d.clone(), value_for(11170449401992604703u64));

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = self.add(c.clone(), d.clone(), layouter);
        // Self::assert_values_are_equal(c.clone(), value_for(2270897969802886507u64));

        // v[b] = rotr_64(v[b] ^ v[c], 63);
        let b_xor_c = self.xor(b.clone(), c.clone(), layouter);
        let b = self.rotate_right_63(b_xor_c, layouter);

        state[a_] = a;
        state[b_] = b;
        state[c_] = c;
        state[d_] = d;

        Ok(())
    }

    pub fn compress(
        &mut self,
        layouter: &mut impl Layouter<F>,
        iv_constants: &[AssignedCell<F, F>; 8],
        global_state: &mut [AssignedCell<F, F>; 8],
        block: [Value<F>; 16],
        processed_bytes_count: Value<F>,
        is_last_block: bool,
    ) -> Result<(), Error> {
        let current_block_words =
            block.map(|input| self.new_row_from_value(input, layouter).unwrap());

        let mut state_vector: Vec<AssignedCell<F, F>> = Vec::new();
        state_vector.extend_from_slice(global_state);
        state_vector.extend_from_slice(iv_constants);

        let mut state: [AssignedCell<F, F>; 16] = state_vector.try_into().unwrap();

        // accumulative_state[12] ^= processed_bytes_count
        let processed_bytes_count_cell =
            self.new_row_from_value(processed_bytes_count, layouter)?;
        state[12] = self.xor(
            state[12].clone(),
            processed_bytes_count_cell.clone(),
            layouter,
        );
        // accumulative_state[13] ^= ctx.processed_bytes_count[1]; This is 0 so we ignore it

        if is_last_block {
            state[14] = self.not(state[14].clone(), layouter);
        }

        // Self::_assert_state_is_correct_before_mixing(&state);

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
                    &current_block_words,
                    layouter,
                )?;
            }
        }

        for i in 0..8 {
            global_state[i] = self.xor(global_state[i].clone(), state[i].clone(), layouter);
            global_state[i] = self.xor(global_state[i].clone(), state[i + 8].clone(), layouter);
        }
        Ok(())
    }

    pub fn compute_initial_state(
        &mut self,
        layouter: &mut impl Layouter<F>,
        iv_constants: &[AssignedCell<F, F>; 8],
        init_const_state_0: AssignedCell<F, F>,
        output_size_constant: AssignedCell<F, F>,
    ) -> Result<[AssignedCell<F, F>; 8], Error> {
        let mut global_state = Self::iv_constants()
            .map(|constant| self.new_row_from_value(constant, layouter).unwrap());

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

        // state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        global_state[0] = self.xor(
            global_state[0].clone(),
            init_const_state_0.clone(),
            layouter,
        );
        global_state[0] = self.xor(global_state[0].clone(), output_size_constant, layouter);
        Ok(global_state)
    }

    pub fn assign_output_size_to_fixed_cell(
        &self,
        layouter: &mut impl Layouter<F>,
        output_size: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "output size",
            |mut region| region.assign_fixed(|| "output size", self.constants, 9, || output_size),
        )
    }

    pub fn assign_01010000_constant_to_fixed_cell(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "constant",
            |mut region| {
                region.assign_fixed(
                    || "state 0 xor",
                    self.constants,
                    8,
                    || value_for(0x01010000u64),
                )
            },
        )
    }

    pub fn assign_iv_constants_to_fixed_cells(
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

    pub fn compute_processed_bytes_count_value_for_iteration(
        iteration: usize,
        is_last_block: bool,
        input_size: Value<F>,
    ) -> Value<F> {
        if is_last_block {
            input_size
        } else {
            let bytes_count_for_iteration = Value::known(F::from(128));
            let iteration_value = Value::known(F::from(iteration as u64));
            bytes_count_for_iteration
                .and_then(|a| iteration_value.and_then(|b| Value::known(a + b)))
        }
    }

    pub fn perform_blake2b_iterations<const BLOCKS: usize>(
        &mut self,
        layouter: &mut impl Layouter<F>,
        input_size: Value<F>,
        input_blocks: [[Value<F>; 16]; BLOCKS],
        iv_constants: &[AssignedCell<F, F>; 8],
        mut global_state: &mut [AssignedCell<F, F>; 8],
    ) -> Result<(), Error> {
        for i in 0..BLOCKS {
            let is_last_block = i == BLOCKS - 1;

            let processed_bytes_count =
                Blake2bTable16Chip::compute_processed_bytes_count_value_for_iteration(
                    i,
                    is_last_block,
                    input_size,
                );
            self.compress(
                layouter,
                iv_constants,
                &mut global_state,
                input_blocks[i],
                processed_bytes_count,
                is_last_block,
            )?;
        }
        Ok(())
    }

    pub fn constraint_public_inputs_to_equal_computation_results(
        &self,
        layouter: &mut impl Layouter<F>,
        global_state: [AssignedCell<F, F>; 8],
    ) -> Result<(), Error> {
        for i in 0..8 {
            layouter.constrain_instance(global_state[i].cell(), self.expected_final_state, i)?;
        }
        Ok(())
    }

    pub fn compute_blake2b_hash_for_inputs<const BLOCKS: usize>(
        &mut self,
        layouter: &mut impl Layouter<F>,
        output_size: Value<F>,
        input_size: Value<F>,
        input_blocks: [[Value<F>; 16]; BLOCKS],
    ) -> Result<(), Error> {
        let iv_constants: [AssignedCell<F, F>; 8] =
            self.assign_iv_constants_to_fixed_cells(layouter);
        let init_const_state_0 = self.assign_01010000_constant_to_fixed_cell(layouter)?;
        let output_size_constant = self.assign_output_size_to_fixed_cell(layouter, output_size)?;
        let mut global_state = self.compute_initial_state(
            layouter,
            &iv_constants,
            init_const_state_0,
            output_size_constant,
        )?;

        self.perform_blake2b_iterations::<BLOCKS>(
            layouter,
            input_size,
            input_blocks,
            &iv_constants,
            &mut global_state,
        )?;

        self.constraint_public_inputs_to_equal_computation_results(layouter, global_state)
    }

    fn _populate_lookup_table_8(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    fn _populate_lookup_table_16(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_16_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
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

    pub fn iv_constants() -> [Value<F>; 8] {
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
