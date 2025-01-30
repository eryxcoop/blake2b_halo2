use super::*;
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};
use crate::chips::decomposition_trait::Decomposition;
use crate::chips::negate_chip::NegateChip;

#[derive(Clone, Debug)]
pub struct Blake2bTable16Chip<F: PrimeField> {
    addition_chip: AdditionMod64Chip<F, 8, 10>,
    decompose_8_chip: Decompose8Chip<F>,
    generic_limb_rotation_chip: LimbRotationChip<F>,
    rotate_63_chip: Rotate63Chip<F, 8, 9>,
    xor_chip: XorChip<F>,
    negate_chip: NegateChip<F>,
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
        let negate_chip = NegateChip::configure(meta, full_number_u64);

        Self {
            addition_chip,
            decompose_8_chip,
            generic_limb_rotation_chip,
            rotate_63_chip,
            xor_chip,
            negate_chip,
        }
    }

    pub fn initialize_with(&mut self, layouter: &mut impl Layouter<F>) {
        self._populate_lookup_table(layouter);
        self._populate_xor_lookup_table(layouter);
    }

    pub fn add(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        /// TODO: La copy constraint podría (y creo que debería) estar en la operación
        let value_a: Value<F> = lhs.value().copied();
        let value_b: Value<F> = rhs.value().copied(); 
        self
            .addition_chip
            .generate_addition_rows(layouter, value_a, value_b, &mut self.decompose_8_chip)
            .unwrap()[0]
            .clone()

    }

    pub fn not(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        let value_a: Value<F> = input_cell.value().copied();
        self
            .negate_chip
            .generate_rows(layouter, value_a, &mut self.decompose_8_chip)
            .unwrap()

    }

    pub fn xor(
        &mut self,
        lhs: AssignedCell<F, F>,
        rhs: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {

        // TODO hacer copy constraints con las nuevas filas generadas
        let value_a: Value<F> = lhs.value().copied();
        let value_b: Value<F> = rhs.value().copied();
        self
            .xor_chip
            .generate_xor_rows(layouter, value_a, value_b, &mut self.decompose_8_chip)
            .unwrap()

    }

    pub fn rotate_right_63(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {

        let value: Value<F> = input_cell.value().copied();

        self
            .rotate_63_chip
            .generate_rotation_rows(layouter, value, &mut self.decompose_8_chip)
            .unwrap()

    }

    pub fn rotate_right_16(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        let value = input_cell.value().copied();

        self
            .generic_limb_rotation_chip
            .generate_rotation_rows(layouter, &mut self.decompose_8_chip, value, 2)
            .unwrap()

    }

    pub fn rotate_right_24(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        let value = input_cell.value().copied();
        self
            .generic_limb_rotation_chip
            .generate_rotation_rows(layouter, &mut self.decompose_8_chip, value, 3)
            .unwrap()

    }

    pub fn rotate_right_32(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        let value = input_cell.value().copied();
        self
            .generic_limb_rotation_chip
            .generate_rotation_rows(layouter, &mut self.decompose_8_chip, value, 4)
            .unwrap()

    }

    pub fn new_row_for(
        &mut self,
        value: Value<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "row",
            |mut region| {
                self.decompose_8_chip.generate_row_from_value(&mut region, value, 0)
            }
        )
    }

    fn _populate_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
    }
}
