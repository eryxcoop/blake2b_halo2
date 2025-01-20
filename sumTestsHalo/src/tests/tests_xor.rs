use super::*;
use crate::auxiliar_functions::value_for;

#[test]
fn test_positive_xor() {
    let valid_xor_trace: [[Value<Fr>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // b
        row_decomposed_in_8_limbs_from_u64(0),                          // a xor b
    ];

    let circuit = XorCircuit::<Fr> {
        _ph: PhantomData,
        trace: valid_xor_trace,
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();

    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_xor_badly_done() {
    let incorrect_xor_trace: [[Value<Fr>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 2) as u64), // b
        row_decomposed_in_8_limbs_from_u64(0),                          // a xor b
    ];

    let circuit = Blake2bCircuit::<Fr>::new_for_xor_alone(incorrect_xor_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_bad_decomposition_in_8_bit_limbs() {
    let mut badly_decomposed_row = [value_for(0u16); 9];
    badly_decomposed_row[4] = value_for(1u16);

    let badly_decomposed_xor_trace: [[Value<Fr>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // b
        badly_decomposed_row,                                           // a xor b
    ];

    let circuit = Blake2bCircuit::<Fr>::new_for_xor_alone(badly_decomposed_xor_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_bad_range_check_limb_u8() {
    let out_of_range_decomposition_row = [
        value_for((1u32 << 16) - 1),
        value_for((1u32 << 16) - 1),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
    ];

    let badly_decomposed_xor_trace: [[Value<Fr>; 9]; 3] = [
        out_of_range_decomposition_row,
        row_decomposed_in_8_limbs_from_u64(0u64), // b
        out_of_range_decomposition_row,           // a xor b
    ];

    let circuit = Blake2bCircuit::<Fr>::new_for_xor_alone(badly_decomposed_xor_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn row_decomposed_in_8_limbs_from_u64(x: u64) -> [Value<Fr>; 9] {
    let mut x_aux = x;
    let mut limbs: [u64; 8] = [0; 8];
    for i in 0..8 {
        limbs[i] = x_aux % 256;
        x_aux /= 256;
    }

    [
        value_for(x),
        value_for(limbs[0]),
        value_for(limbs[1]),
        value_for(limbs[2]),
        value_for(limbs[3]),
        value_for(limbs[4]),
        value_for(limbs[5]),
        value_for(limbs[6]),
        value_for(limbs[7]),
    ]
}

use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem},
};

use ff::Field;

struct XorCircuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 3],
}

impl<F: Field + From<u64>> Circuit<F> for XorCircuit<F> {
    type Config = XorChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        XorCircuit { _ph: PhantomData,  trace: XorChip::_unknown_trace()}
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
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
        let t_range8 = meta.lookup_table_column();

        let decompose_8_chip =
            Decompose8Chip::configure(meta, full_number_u64, limbs_8_bits, t_range8);

        XorChip::configure(
            meta,
            limbs_8_bits,
            decompose_8_chip.clone(),
            full_number_u64,
        )
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_chip.populate_lookup_table8(&mut layouter)?;
        config.populate_xor_lookup_table(&mut layouter)?;
        config.create_xor_region(&mut layouter, self.trace);

        Ok(())
    }
}
