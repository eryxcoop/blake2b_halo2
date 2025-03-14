use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance};
use crate::base_operations::addition_mod_64::AdditionMod64Config;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use crate::base_operations::negate::NegateConfig;
use crate::base_operations::rotate_63::Rotate63Config;
use crate::base_operations::xor::Xor;
use crate::base_operations::xor_spread::XorSpreadConfig;
use crate::blake2b::chips::blake2b_generic::Blake2bGeneric;
/// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
/// It contains all the necessary chips and some extra columns.
///
/// This optimization uses addition with 8 limbs and computes xor with a spread table of 8-bits.
/// Each iteration takes more rows but there's less overhead of creating the 2^16 tables.
#[derive(Clone, Debug)]
pub struct Blake2bChipOptSpread {
    /// Decomposition configs
    decompose_8_config: Decompose8Config,
    /// Base oprerations configs
    addition_config: AdditionMod64Config<8, 10>,
    generic_limb_rotation_config: LimbRotation,
    rotate_63_config: Rotate63Config<8, 9>,
    xor_config: XorSpreadConfig,
    negate_config: NegateConfig,
    /// Column for constants of Blake2b
    constants: Column<Fixed>,
    /// Column for the expected final state of the hash
    expected_final_state: Column<Instance>,
}

impl Blake2bGeneric for Blake2bChipOptSpread {
    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        /// Config that is the same for every optimization
        let (
            decompose_8_config,
            generic_limb_rotation_config,
            rotate_63_config,
            negate_config,
            constants,
            expected_final_state,
        ) = Self::generic_configure(meta, full_number_u64, limbs);

        /// Config that is optimization-specific
        /// An extra carry column is needed for the sum operation with 8 limbs.
        let carry = meta.advice_column();
        let addition_config = AdditionMod64Config::<8, 10>::configure(meta, full_number_u64, carry);

        /// We must provide the spread config all the columns, not just the limbs
        let xor_config = XorSpreadConfig::configure(meta, limbs, full_number_u64, carry);

        Self {
            addition_config,
            decompose_8_config,
            generic_limb_rotation_config,
            rotate_63_config,
            xor_config,
            negate_config,
            constants,
            expected_final_state,
        }
    }

    fn initialize_with<F: PrimeField>(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        /// Initialization that is the same for every optimization
        self.generic_initialize_with(layouter)
    }

    // Getters that the trait needs for its default implementations
    fn decompose_8_config(&mut self) -> Decompose8Config {
        self.decompose_8_config.clone()
    }

    fn generic_limb_rotation_config(&mut self) -> LimbRotation {
        self.generic_limb_rotation_config.clone()
    }

    fn rotate_63_config(&mut self) -> Rotate63Config<8, 9> {
        self.rotate_63_config.clone()
    }

    fn xor_config(&mut self) -> impl Xor {
        self.xor_config.clone()
    }

    fn negate_config(&mut self) -> NegateConfig {
        self.negate_config.clone()
    }

    fn constants(&self) -> Column<Fixed> {
        self.constants
    }

    fn expected_final_state(&self) -> Column<Instance> {
        self.expected_final_state
    }

    // Functions that are optimization-specific

    /// opt_spread optimization decomposes the sum operands in 8-bit limbs, so we need to use the
    /// decompose_8_config for the sum operation instead of the decompose_16_config.
    fn add<F: PrimeField>(
        &mut self,
        lhs: &AssignedCell<F, F>,
        rhs: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let addition_cell = self.addition_config.generate_addition_rows_from_cells_optimized(
            region,
            offset,
            lhs,
            rhs,
            &mut self.decompose_8_config,
            false,
        )?[0]
            .clone();
        Ok(addition_cell)
    }

    /// This method behaves like 'add', with the difference that it takes advantage of the fact that
    /// the last row in the circuit is one of the operands of the addition, so it only needs to copy
    /// one parameter because the other is already on the trace.
    fn add_copying_one_parameter<F: PrimeField>(
        &mut self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        Ok(self.addition_config.generate_addition_rows_from_cells_optimized(
            region,
            offset,
            previous_cell,
            cell_to_copy,
            &mut self.decompose_8_config,
            true,
        )?[0]
            .clone())
    }

    /// This method performs a regular xor operation with the difference that it returns the full
    /// row in the trace, instead of just the cell holding the value. This allows an optimization
    /// where the next operation (which is a rotation) can just read the limbs directly and apply
    /// the limb rotation without copying the operand.
    fn xor_for_mix<F: PrimeField>(
        &mut self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedCell<F, F>; 9], Error> {
        self.xor_copying_one_parameter(previous_cell, cell_to_copy, region, offset)
    }
}

impl Blake2bChipOptSpread {
    /// This method only exists inwith 8-bit limbs sum, so it's defined in a different block.
    /// opt_recycle decomposes the sum operands in 8-bit limbs, so the xor operation that comes after
    /// can recycle the result row of the addition and use it as its first operand.
    fn xor_copying_one_parameter<F: PrimeField>(
        &mut self,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        region: &mut Region<F>,
        offset: &mut usize,
    ) -> Result<[AssignedCell<F, F>; 9], Error> {
        self.xor_config.generate_xor_rows_from_cells(
            region,
            offset,
            previous_cell,
            cell_to_copy,
            &mut self.decompose_8_config,
            true,
        )
    }
}
