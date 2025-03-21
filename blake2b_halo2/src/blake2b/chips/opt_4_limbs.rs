use crate::base_operations::addition_mod_64::AdditionMod64Config;
use crate::base_operations::decompose_16::Decompose16Config;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::decomposition::Decomposition;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::base_operations::xor::Xor;
use crate::base_operations::xor_table::XorTableConfig;
use crate::blake2b::chips::blake2b_generic::Blake2bInstructions;
use crate::types::{AssignedBlake2bWord, AssignedNative};
use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};

/// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
/// It contains all the necessary chips and some extra columns.
///
/// This optimization uses addition with 4 limbs instead of 8, which allows the circuit to have
/// one less column (the carry column). This is because the addition chip of 8 bits uses 10 columns
/// (the maximum amount of columns any chip uses) and the addition chip of 4 bits uses 6 columns
/// (refer to AdditionMod64Config).
///
/// It also computes xor with a table that precomputes all the possible 8-bit operands (refer to
/// XorTableConfig).
#[derive(Clone, Debug)]
pub struct Blake2bChipOpt4Limbs {
    /// Decomposition configs
    decompose_8_config: Decompose8Config,
    decompose_16_config: Decompose16Config,
    /// Base oprerations configs
    addition_config: AdditionMod64Config<4, 6>,
    generic_limb_rotation_config: LimbRotation,
    rotate_63_config: Rotate63Config<8, 9>,
    xor_config: XorTableConfig,
    negate_config: NegateConfig,
}

impl Blake2bInstructions for Blake2bChipOpt4Limbs {
    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        /// Config that is the same for every optimization
        let (decompose_8_config, generic_limb_rotation_config, rotate_63_config, negate_config) =
            Self::generic_configure(meta, full_number_u64, limbs);

        /// Config that is optimization-specific
        let addition_config =
            AdditionMod64Config::<4, 6>::configure(meta, full_number_u64, limbs[0]);
        let xor_config = XorTableConfig::configure(meta, limbs);
        let decompose_16_config =
            Decompose16Config::configure(meta, full_number_u64, limbs[0..4].try_into().unwrap());

        Self {
            addition_config,
            decompose_8_config,
            decompose_16_config,
            generic_limb_rotation_config,
            rotate_63_config,
            xor_config,
            negate_config,
        }
    }

    fn populate_lookup_tables<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.populate_lookup_table_8(layouter)?;
        self.populate_xor_lookup_table(layouter)?;
        self.populate_lookup_table_16(layouter)
    }

    // Getters that the trait needs for its default implementations
    fn decompose_8_config(&self) -> Decompose8Config {
        self.decompose_8_config.clone()
    }

    fn generic_limb_rotation_config(&self) -> LimbRotation {
        self.generic_limb_rotation_config.clone()
    }

    fn rotate_63_config(&self) -> Rotate63Config<8, 9> {
        self.rotate_63_config.clone()
    }

    fn xor_config(&self) -> impl Xor {
        self.xor_config.clone()
    }

    fn negate_config(&self) -> NegateConfig {
        self.negate_config.clone()
    }

    // Functions that are optimization-specific

    /// opt_4_limbs optimization decomposes the sum operands in 16-bit limbs, so we need to use the
    /// decompose_16_config for the sum operation instead of the decompose_8_config.
    fn add<F: PrimeField>(
        &self,
        lhs: &AssignedNative<F>,
        rhs: &AssignedNative<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedNative<F>, Error> {
        let addition_cell = self.addition_config.generate_addition_rows_from_cells(
            region,
            offset,
            lhs,
            rhs,
            &self.decompose_16_config,
            false,
        )?[0]
            .clone();
        Ok(addition_cell)
    }

    /// This method behaves like 'add', with the difference that it takes advantage of the fact that
    /// the last row in the circuit is one of the operands of the addition, so it only needs to copy
    /// one parameter because the other is already on the trace.
    fn add_copying_one_parameter<F: PrimeField>(
        &self,
        previous_cell: &AssignedNative<F>,
        cell_to_copy: &AssignedNative<F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedNative<F>, Error> {
        Ok(self.addition_config.generate_addition_rows_from_cells(
            region,
            offset,
            previous_cell,
            cell_to_copy,
            &self.decompose_16_config,
            true,
        )?[0]
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
    ) -> Result<[AssignedNative<F>; 9], Error> {
        self.xor_with_full_rows(previous_cell, cell_to_copy, region, offset)
    }
}

impl Blake2bChipOpt4Limbs {
    /// This method only exists in the opt_4_limbs optimization, so it's defined in a different block.
    /// opt_4_limbs decomposes the sum operands in 16-bit limbs, so we need to range check them with
    /// a 16-bit lookup table. This method initializes it
    fn populate_lookup_table_16<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.decompose_16_config.populate_lookup_table(layouter)
    }
}
