use crate::chips::decompose_8_chip::Decompose8Chip;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;

use crate::chips::decomposition_trait::Decomposition;

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
        decompose_8_chip: Decompose8Chip<F>,
        addition_chip: AdditionMod64Chip<F, 8, 10>,
        generic_limb_rotation_chip: LimbRotationChip<F>,
        rotate_63_chip: Rotate63Chip<F, 8, 9>,
        xor_chip: XorChip<F>,
    ) -> Self {
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

    pub fn add(&mut self, value_a: Value<F>, value_b: Value<F>, layouter: &mut impl Layouter<F>) -> Value<F> {
        let addition_result = self.addition_chip.generate_addition_rows(
            layouter, value_a, value_b, &mut self.decompose_8_chip).unwrap()[0].clone();

        addition_result.value().copied()
    }

    pub fn xor(&mut self, value: Value<F>, b: Value<F>, layouter: &mut impl Layouter<F>) -> Value<F> {
        let xor_result = self.xor_chip.generate_xor_rows(
            layouter, value, b, &mut self.decompose_8_chip).unwrap();

        xor_result.value().copied()
    }

    pub fn rotate_right_63(&mut self, value: Value<F>, layouter: &mut impl Layouter<F>) -> Value<F> {
        let rotate_result = self.rotate_63_chip.generate_rotation_rows(
            layouter, value, &mut self.decompose_8_chip).unwrap();

        rotate_result.value().copied()
    }

    pub fn rotate_right_16(&mut self, value: Value<F>, layouter: &mut impl Layouter<F>) -> Value<F> {
        let rotate_result = self.generic_limb_rotation_chip.generate_rotation_rows(
            layouter, &mut self.decompose_8_chip, value, 2).unwrap();

        rotate_result.value().copied()
    }

    pub fn rotate_right_24(&mut self, value: Value<F>, layouter: &mut impl Layouter<F>) -> Value<F> {
        let rotate_result = self.generic_limb_rotation_chip.generate_rotation_rows(
            layouter, &mut self.decompose_8_chip, value, 3).unwrap();

        rotate_result.value().copied()
    }

    pub fn rotate_right_32(&mut self, value: Value<F>, layouter: &mut impl Layouter<F>) -> Value<F> {
        let rotate_result = self.generic_limb_rotation_chip.generate_rotation_rows(
            layouter, &mut self.decompose_8_chip, value, 4).unwrap();

        rotate_result.value().copied()
    }

    fn _populate_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
    }
}