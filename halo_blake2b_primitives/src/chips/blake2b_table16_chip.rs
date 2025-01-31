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
        self
            .generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 2)
            .unwrap()

    }

    pub fn rotate_right_24(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self
            .generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 3)
            .unwrap()

    }

    pub fn rotate_right_32(
        &mut self,
        input_cell: AssignedCell<F, F>,
        layouter: &mut impl Layouter<F>,
    ) -> AssignedCell<F, F> {
        self
            .generic_limb_rotation_chip
            .generate_rotation_rows_from_cell(layouter, &mut self.decompose_8_chip, input_cell, 4)
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

    pub fn mix(
        &mut self, a_: usize, b_: usize, c_: usize, d_: usize, sigma_even: usize, sigma_odd: usize,
        state: &mut [AssignedCell<F, F>; 16], current_block_words: &[AssignedCell<F, F>; 16],
        layouter: &mut impl Layouter<F>) -> Result<(), Error> {
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

    fn _populate_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.decompose_8_chip.populate_lookup_table(layouter);
    }

    fn _populate_xor_lookup_table(&mut self, layouter: &mut impl Layouter<F>) {
        let _ = self.xor_chip.populate_xor_lookup_table(layouter);
    }
}
