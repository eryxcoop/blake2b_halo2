use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem},
};

use crate::chips::decompose_16_chip::Decompose16Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::rotate_24_chip::Rotate24Chip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::sum_mod64_chip::SumMod64Chip;
use crate::chips::xor_chip::XorChip;
use ff::Field;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

struct Blake2bCircuit<F: Field> {
    _ph: PhantomData<F>,
    addition_trace: [[Value<F>; 6]; 3],
    rotation_trace_63: [[Value<F>; 5]; 2],
    rotation_trace_24: [[Value<F>; 5]; 3],
    xor_trace: [[Value<F>; 9]; 3],
    should_create_xor_table: bool,
}

#[derive(Clone, Debug)]
struct Blake2bConfig<F: Field + Clone> {
    full_number_u64: Column<Advice>,

    // Working with 4 limbs of u16
    limbs: [Column<Advice>; 4],
    carry: Column<Advice>,
    t_range8: TableColumn,
    rotate_63_chip: Rotate63Chip<F>,
    rotate_24_chip: Rotate24Chip<F>,
    sum_mod64_chip: SumMod64Chip<F>,
    decompose_16_chip: Decompose16Chip<F>,

    // Working with 8 limbs of u8
    limbs_8_bits: [Column<Advice>; 8],
    xor_chip: XorChip<F>,
    decompose_8_chip: Decompose8Chip<F>,

    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Circuit<F> for Blake2bCircuit<F> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Blake2bCircuit::new_for_unknown_values()
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Addition
        let full_number_u64 = meta.advice_column();
        let limbs = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for limb in limbs {
            meta.enable_equality(limb);
        }
        let t_range8 = meta.lookup_table_column();
        let carry = meta.advice_column();

        let decompose_16_chip = Decompose16Chip::configure(meta, full_number_u64, limbs);

        let sum_mod64_chip = SumMod64Chip::configure(
            meta,
            limbs,
            decompose_16_chip.clone(),
            full_number_u64,
            carry,
        );

        // Rotation
        let rotate_63_chip = Rotate63Chip::configure(meta, full_number_u64);

        // config for xor
        let limbs_8_bits = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let decompose_8_chip =
            Decompose8Chip::configure(meta, full_number_u64, limbs_8_bits, t_range8);

        // Rotation 24
        let rotate_24_chip = Rotate24Chip::configure(meta, full_number_u64, limbs, decompose_8_chip.clone());

        // Xor
        let xor_chip = XorChip::configure(
            meta,
            limbs_8_bits,
            decompose_8_chip.clone(),
            full_number_u64,
        );

        Blake2bConfig {
            _ph: PhantomData,
            decompose_8_chip,
            decompose_16_chip,
            xor_chip,
            sum_mod64_chip,
            rotate_63_chip,
            rotate_24_chip,
            full_number_u64,
            limbs,
            carry,
            limbs_8_bits,
            t_range8,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .sum_mod64_chip
            .assign_addition_rows(&mut layouter, self.addition_trace);

        config.decompose_16_chip.populate_lookup_table16(&mut layouter)?;

        // Rotation
        config.rotate_63_chip.assign_rotation_rows(
            &mut layouter,
            &mut config.decompose_16_chip,
            self.rotation_trace_63,
        );
        config.rotate_24_chip.assign_rotation_rows(
            &mut layouter,
            &mut config.decompose_16_chip,
            self.rotation_trace_24,
        );

        config.decompose_8_chip.populate_lookup_table8(&mut layouter)?;

        // XOR operation

        if self.should_create_xor_table {
            config.xor_chip.populate_xor_lookup_table(&mut layouter)?;
            config
                .xor_chip
                .create_xor_region(&mut layouter, self.xor_trace);
        }

        Ok(())
    }
}

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn _unknown_trace_for_rotation_63() -> [[Value<F>; 5]; 2] {
        [[Value::unknown(); 5]; 2]
    }

    fn _unknown_trace_for_addition() -> [[Value<F>; 6]; 3] {
        [[Value::unknown(); 6]; 3]
    }

    fn _unknown_trace_for_rotation_24() -> [[Value<F>; 5]; 3] {
        [[Value::unknown(); 5]; 3]
    }

    fn _unknown_trace_for_xor() -> [[Value<F>; 9]; 3] {
        XorChip::_unknown_trace()
    }

    fn new_for_unknown_values() -> Self {
        Blake2bCircuit {
            _ph: PhantomData,
            addition_trace: Self::_unknown_trace_for_addition(),
            rotation_trace_63: Self::_unknown_trace_for_rotation_63(),
            rotation_trace_24: Self::_unknown_trace_for_rotation_24(),
            xor_trace: Self::_unknown_trace_for_xor(),
            should_create_xor_table: false,
        }
    }
}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;
    let circuit = Blake2bCircuit::<Fr>::new_for_unknown_values();
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

pub mod auxiliar_functions;
pub mod chips;
#[cfg(test)]
pub mod tests;
