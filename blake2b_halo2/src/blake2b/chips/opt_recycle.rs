use crate::base_operations::addition_mod_64::AdditionMod64Config;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::base_operations::xor::Xor;
use crate::base_operations::xor_table::XorTableConfig;
use crate::blake2b::chips::blake2b_instructions::Blake2bInstructions;
use crate::types::{AssignedBlake2bWord, AssignedElement, AssignedNative, AssignedRow};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};
use crate::base_operations::decomposition::Decomposition;

/// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
/// It contains all the necessary chips and some extra columns.
///
/// This optimization uses addition with 8 limbs and computes xor with a table that precomputes
/// all the possible 8-bit operands. Since all operations have operands with 8-bit decompositions,
/// we can recycle (hence the name) some rows per iteration of the algorithm for every operation.
#[derive(Clone, Debug)]
pub struct Blake2bChipOptRecycle {
    /// Decomposition configs
    decompose_8_config: Decompose8Config,
    /// Base oprerations configs
    addition_config: AdditionMod64Config,
    generic_limb_rotation_config: LimbRotation,
    rotate_63_config: Rotate63Config,
    xor_config: XorTableConfig,
    negate_config: NegateConfig,
    /// Advice columns
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
}

impl Blake2bInstructions for Blake2bChipOptRecycle {
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
        let xor_config = XorTableConfig::configure(meta, limbs);

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

    // Getters that the trait needs for its default implementations
    fn decompose_8_config(&self) -> Decompose8Config {
        self.decompose_8_config.clone()
    }

    fn get_limb_column(&self, index: usize) -> Column<Advice> {
        self.limbs[index]
    }

    fn get_full_number_column(&self) -> Column<Advice> {
        self.full_number_u64
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
        let cell = self.negate_config.generate_rows_from_cell(
            region,
            offset,
            &input_cell.inner_value(),
            self.get_full_number_column(),
        )?;
        Ok(AssignedBlake2bWord::<F>::new(cell))
    }

    fn xor_and_return_full_row<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedRow<F>, Error> {
        let decompose_8_config = self.decompose_8_config();
        let row = self.xor_config.generate_xor_rows_from_cells(
            region,
            offset,
            lhs,
            rhs,
            &decompose_8_config,
            false,
        )?;

        Ok(AssignedRow::<F>::new_from_native(row))
    }

    fn xor<F: PrimeField>(
        &self,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let decompose_8_config = self.decompose_8_config();
        let full_number_cell = self.xor_config.generate_xor_rows_from_cells(
            region,
            offset,
            &lhs,
            &rhs,
            &decompose_8_config,
            false,
        )?[0]
            .clone();
        Ok(AssignedBlake2bWord::<F>::new(full_number_cell))
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
            &lhs.inner_value(),
            &rhs.inner_value(),
            &self.decompose_8_config,
            false,
        )?[0]
            .clone();
        Ok(AssignedBlake2bWord::<F>::new(addition_cell))
    }

    fn rotate_right_63<F: PrimeField>(
        &self,
        input_row: [AssignedNative<F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        Ok(AssignedBlake2bWord::<F>::new(self.rotate_63_config.generate_rotation_rows_from_cells(
            region,
            offset,
            &input_row[0],
            self.get_full_number_column(),
        )?))
    }

    fn rotate_right_16<F: PrimeField>(
        &self,
        input_row: [AssignedNative<F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        Ok(AssignedBlake2bWord::<F>::new(self.generic_limb_rotation_config.generate_rotation_rows_from_input_row(
            region,
            offset,
            &mut decompose_8_config,
            input_row,
            2,
        )?))
    }

    fn rotate_right_24<F: PrimeField>(
        &self,
        input_row: [AssignedNative<F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        Ok(AssignedBlake2bWord::<F>::new(self.generic_limb_rotation_config.generate_rotation_rows_from_input_row(
            region,
            offset,
            &mut decompose_8_config,
            input_row,
            3,
        )?))
    }

    fn rotate_right_32<F: PrimeField>(
        &self,
        input_row: [AssignedNative<F>; 9],
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let mut decompose_8_config = self.decompose_8_config();
        Ok(AssignedBlake2bWord::<F>::new(self.generic_limb_rotation_config.generate_rotation_rows_from_input_row(
            region,
            offset,
            &mut decompose_8_config,
            input_row,
            4,
        )?))
    }
}

impl Blake2bChipOptRecycle {
    /// This method only exists in the opt_recycle optimization, so it's defined in a different block.
    /// opt_recycle decomposes the sum operands in 8-bit limbs, so the xor operation that comes after
    /// can recycle the result row of the addition and use it as its first operand.
    fn xor_copying_one_parameter<F: PrimeField>(
        &self,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedNative<F>; 9], Error> {
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
        self.decompose_8_config().populate_lookup_table(layouter)
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
        Ok(AssignedBlake2bWord::<F>::new(self.addition_config.generate_addition_rows_from_cells(
            region,
            offset,
            &previous_cell.inner_value(),
            &cell_to_copy.inner_value(),
            &self.decompose_8_config,
            true,
        )?[0]
            .clone()))
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
    ) -> Result<[AssignedNative<F>; 9], Error> {
        self.xor_copying_one_parameter(previous_cell, cell_to_copy, region, offset)
    }
}
