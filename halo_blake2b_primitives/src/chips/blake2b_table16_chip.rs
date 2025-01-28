use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};
use crate::chips::decomposition_trait::Decomposition;

#[derive(Clone, Debug)]
pub enum Operand<F: PrimeField> {
    Cell(AssignedCell<F,F>),
    Value(Value<F>)
}

#[derive(Clone, Debug)]
pub struct Blake2bTable16Chip<F: PrimeField> {
    addition_chip: AdditionMod64Chip<F, 8, 10>,
    decompose_8_chip: Decompose8Chip<F>,
    generic_limb_rotation_chip: LimbRotationChip<F>,
    rotate_63_chip: Rotate63Chip<F, 8, 9>,
    xor_chip: XorChip<F>,
}

impl<F: PrimeField> Blake2bTable16Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>, full_number_u64: Column<Advice>, limbs: [Column<Advice>; 8],
        carry: Column<Advice>,
    ) -> Self {
        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);
        let addition_chip = AdditionMod64Chip::<F, 8, 10>::configure(meta, full_number_u64, carry);
        let generic_limb_rotation_chip = LimbRotationChip::new();
        let rotate_63_chip = Rotate63Chip::configure(meta, full_number_u64);
        let xor_chip = XorChip::configure(meta, limbs);

        Self {
            addition_chip,
            decompose_8_chip,
            generic_limb_rotation_chip,
            rotate_63_chip,
            xor_chip,
        }
    }

    pub fn initialize_with(&mut self, layouter: &mut impl Layouter<F>) {
        self._populate_lookup_table(layouter);
        self._populate_xor_lookup_table(layouter);
    }

    pub fn add(
        &mut self,
        operand_a: Operand<F>,
        operand_b: Operand<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Operand<F> {
        /// TODO: La copy constraint podría (y creo que debería) estar en la operación
        let value_a: Value<F> = Self::_obtain_value_from_operand(operand_a);
        let value_b: Value<F> = Self::_obtain_value_from_operand(operand_b);

        let addition_result = self
            .addition_chip
            .generate_addition_rows(layouter, value_a, value_b, &mut self.decompose_8_chip)
            .unwrap()[0]
            .clone();

        Self::operand_from(addition_result)
    }

    fn operand_from(cell: AssignedCell<F, F>) -> Operand<F> {
        Operand::Cell(cell)
    }

    pub fn xor(
        &mut self,
        operand_a: Operand<F>,
        operand_b: Operand<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Operand<F> {

        let value_a: Value<F> = Self::_obtain_value_from_operand(operand_a);
        let value_b: Value<F> = Self::_obtain_value_from_operand(operand_b);
        let xor_result = self
            .xor_chip
            .generate_xor_rows(layouter, value_a, value_b, &mut self.decompose_8_chip)
            .unwrap();

        Self::operand_from(xor_result)
    }

    pub fn rotate_right_63(
        &mut self,
        operand: Operand<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Operand<F> {

        let value: Value<F> = Self::_obtain_value_from_operand(operand);

        let rotate_result = self
            .rotate_63_chip
            .generate_rotation_rows(layouter, value, &mut self.decompose_8_chip)
            .unwrap();

        Self::operand_from(rotate_result)
    }

    pub fn rotate_right_16(
        &mut self,
        operand: Operand<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Operand<F> {
        let value = Self::_obtain_value_from_operand(operand);

        let rotate_result = self
            .generic_limb_rotation_chip
            .generate_rotation_rows(layouter, &mut self.decompose_8_chip, value, 2)
            .unwrap();

        Self::operand_from(rotate_result)
    }

    pub fn rotate_right_24(
        &mut self,
        operand: Operand<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Operand<F> {
        let value = Self::_obtain_value_from_operand(operand);
        let rotate_result = self
            .generic_limb_rotation_chip
            .generate_rotation_rows(layouter, &mut self.decompose_8_chip, value, 3)
            .unwrap();

        Self::operand_from(rotate_result)
    }

    pub fn rotate_right_32(
        &mut self,
        operand: Operand<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Operand<F> {
        let value = Self::_obtain_value_from_operand(operand);
        let rotate_result = self
            .generic_limb_rotation_chip
            .generate_rotation_rows(layouter, &mut self.decompose_8_chip, value, 4)
            .unwrap();

        Self::operand_from(rotate_result)
    }

    fn _populate_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
    }

    fn _obtain_value_from_operand(operand_a: Operand<F>) -> Value<F> {
        match operand_a {
            Operand::Cell(operand_a) => {
                operand_a.value().copied()
            },
            Operand::Value(operand_a) => {
                operand_a
            }
        }
    }
}
