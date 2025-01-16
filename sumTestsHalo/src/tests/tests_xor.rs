use super::*;
use crate::auxiliar_functions::value_for;

#[test]
fn test_positive_xor() {
    let valid_xor_trace: [[Value<Fr>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // b
        row_decomposed_in_8_limbs_from_u64(0),                          // a xor b
    ];

    let circuit = Blake2bCircuit::<Fr>::new_for_xor_alone(valid_xor_trace);
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
    let mut badly_decomposed_row = [value_for(0); 9];
    badly_decomposed_row[4] = value_for(1);

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
    // TODO: check why this test is passing when not enforced the range check
    let out_of_range_decomposition_row = [
        value_for((1 << 16) - 1),
        value_for((1 << 16) - 1),
        value_for(0),
        value_for(0),
        value_for(0),
        value_for(0),
        value_for(0),
        value_for(0),
        value_for(0),
    ];

    let badly_decomposed_xor_trace: [[Value<Fr>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64 - ((1 << 16) - 1) as u64), // b
        out_of_range_decomposition_row, // a xor b
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
