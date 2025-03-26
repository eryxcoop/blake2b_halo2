use crate::base_operations::addition_mod_64::AdditionMod64Config;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::base_operations::xor::XorConfig;
use crate::blake2b::chips::blake2b_instructions::Blake2bInstructions;
use crate::types::{AssignedBlake2bWord, AssignedElement, AssignedNative, AssignedRow};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};
use crate::blake2b::chips::utils::BLAKE2B_BLOCK_SIZE;

/// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
/// It contains all the necessary chips and some extra columns.
///
/// This optimization uses addition with 8 limbs and computes xor with a table that precomputes
/// all the possible 8-bit operands. Since all operations have operands with 8-bit decompositions,
/// we can recycle (hence the name) some rows per iteration of the algorithm for every operation.
#[derive(Clone, Debug)]
pub struct Blake2bChip {
    /// Decomposition configs
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
    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        /// Config that is the same for every optimization
        let (decompose_8_config, generic_limb_rotation_config, rotate_63_config, negate_config) =
            Self::generic_configure(meta, full_number_u64, limbs);

        /// Config that is optimization-specific
        /// An extra carry column is needed for the sum operation with 8 limbs.
        let addition_config = AdditionMod64Config::configure(meta, full_number_u64, limbs[0]);
        let xor_config = XorConfig::configure(meta, limbs);

        Self {
            addition_config,
            decompose_8_config,
            generic_limb_rotation_config,
            rotate_63_config,
            xor_config,
            negate_config,
            full_number_u64,
            limbs
        }
    }

    fn populate_lookup_tables<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.populate_lookup_table_8(layouter)?;
        self.populate_xor_lookup_table(layouter)
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
    ) -> Result<(), Error> {
        let v_a = state[a_index].clone();
        let v_b = state[b_index].clone();
        let v_c = state[c_index].clone();
        let v_d = state[d_index].clone();
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

        state[a_index] = a;
        state[b_index] = b;
        state[c_index] = c;
        state[d_index] = d;

        Ok(())
    }

    // Functions that are optimization-specific

    fn not<F: PrimeField>(
        &self,
        input_cell: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.negate_config.generate_rows_from_cell(
            region,
            offset,
            input_cell,
            self.full_number_u64,
        )
    }

    fn xor_and_return_full_row<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error> {
        let row = self.xor_config.generate_xor_rows_from_cells(
            region,
            offset,
            lhs,
            rhs,
            &self.decompose_8_config,
            false,
        )?;

        Ok(row)
    }

    fn xor<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let full_number_cell = self.xor_config.generate_xor_rows_from_cells(
            region,
            offset,
            &lhs,
            &rhs,
            &self.decompose_8_config,
            false,
        )?.full_number
            .clone();
        Ok(full_number_cell)
    }

    /// opt_recycle optimization decomposes the sum operands in 8-bit limbs, so we need to use the
    /// decompose_8_config for the sum operation instead of the decompose_16_config.
    fn add<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let addition_cell = self.addition_config.generate_addition_rows_from_cells(
            region,
            offset,
            lhs,
            rhs,
            &self.decompose_8_config,
            false,
            self.full_number_u64,
        )?.0
            .clone();
        Ok(addition_cell)
    }

    fn rotate_right_63<F: PrimeField>(
        &self,
        input_row: AssignedRow<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.rotate_63_config.generate_rotation_rows_from_cells(
            region,
            offset,
            &input_row.full_number,
            self.full_number_u64,
        )
    }

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

    fn assign_full_number_constant<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &usize,
        description: &str,
        constant: u64
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        Ok(AssignedBlake2bWord::<F>::new(
            region.assign_advice_from_constant(
                || description,
                self.full_number_u64,
                *row_offset,
                F::from(constant),
            )?))
    }

    fn assign_limb_constant_u64<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row_offset: &usize,
        description: &str,
        constant: u64,
        limb_index: usize
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        Ok(AssignedBlake2bWord::<F>::new(
        region.assign_advice_from_constant(
            || description,
            self.limbs[limb_index],
            *row_offset,
            F::from(constant),
        )?))
    }
}

impl Blake2bChip {
    /// This method only exists in the opt_recycle optimization, so it's defined in a different block.
    /// opt_recycle decomposes the sum operands in 8-bit limbs, so the xor operation that comes after
    /// can recycle the result row of the addition and use it as its first operand.
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
            &self.decompose_8_config,
            true,
        )
    }

    fn populate_lookup_table_8<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.decompose_8_config.populate_lookup_table(layouter)
    }

    fn populate_xor_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.xor_config.populate_xor_lookup_table(layouter)
    }

    /// This method behaves like 'add', with the difference that it takes advantage of the fact that
    /// the last row in the circuit is one of the operands of the addition, so it only needs to copy
    /// one parameter because the other is already on the trace.
    fn add_copying_one_parameter<F: PrimeField>(
        &self,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        Ok(self.addition_config.generate_addition_rows_from_cells(
            region,
            offset,
            previous_cell,
            cell_to_copy,
            &self.decompose_8_config,
            true,
            self.full_number_u64,
        )?.0
            .clone())
    }

    /// This method performs a regular xor operation with the difference that it returns the full
    /// row in the trace, instead of just the cell holding the value. This allows an optimization
    /// where the next operation (which is a rotation) can just read the limbs directly and apply
    /// the limb rotation without copying the operand.
    fn xor_for_mix<F: PrimeField>(
        &self,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.xor_copying_one_parameter(previous_cell, cell_to_copy, region, offset)
    }

    /// Given an array of byte-values, it puts in the circuit a full row with those bytes in the
    /// limbs and the resulting full number in the first column.
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
    /// the block number we're on.
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
            let current_input_block_index = if is_key_empty { block_number } else { block_number - 1 };
            input[current_input_block_index * BLAKE2B_BLOCK_SIZE
                ..(current_input_block_index + 1) * BLAKE2B_BLOCK_SIZE]
                .to_vec()
        }
    }
}
