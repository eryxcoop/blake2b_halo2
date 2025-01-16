use super::*;
use crate::auxiliar_functions::{spread, trash, value_for};

#[test]
fn test_positive_xor() {
    let first_row = xor_row_from_u64(((1u128 << 64) - 1) as u64);
    let second_row = xor_row_from_u64(((1u128 << 64) - 1) as u64);
    let last_row = xor_row_from_u64(0);

    let trace: [[Value<Fr>; 9]; 3] = [
        first_row,  // a
        second_row, // b
        last_row,   // a xor b
    ];

    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: [[Value::unknown(); 6]; 3],
        rotation_trace_63: [[Value::unknown(); 5]; 2],
        rotation_trace_24: [[Value::unknown(); 5]; 3],
        xor_trace: trace,
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn xor_row_from_u64(x: u64) -> [Value<Fr>; 9] {
    // x
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
