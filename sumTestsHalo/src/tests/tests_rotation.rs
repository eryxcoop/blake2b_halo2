use super::*;
use crate::Blake2bCircuit;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use std::marker::PhantomData;

#[test]
fn test_positive_rotate_right_63() {
    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_63(valid_rotation_trace_63());
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_63() {
    let mut invalid_rotation_trace = [
        [one(), one(), zero(), zero(), zero()],
        [one() + one(), one() + one(), zero(), zero(), zero()],
    ];
    invalid_rotation_trace[0][1] = one() + invalid_rotation_trace[0][1];
    invalid_rotation_trace[0][0] = one() + invalid_rotation_trace[0][0];

    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_63(invalid_rotation_trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_rotate_right_24() {
    let rotation_trace = valid_rotation24_trace();
    _test_rotate24(rotation_trace);
}

#[test]
fn test_positive_rotate_right_24_b() {
    let rotation_trace = [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        [max_u40(), max_u16(), max_u16(), max_u8(), zero()],
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
    ];
    _test_rotate24(rotation_trace);
}

#[test]
#[should_panic]
fn test_negative_rotate_right_24() {
    let rotation_trace = [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        [max_u40(), max_u16(), max_u16(), max_u8(), zero()],
        [one(), one(), zero(), zero(), zero()],
    ];
    _test_rotate24(rotation_trace);
}

#[test]
#[should_panic]
fn test_rotate_right_24_chunk_out_of_range() {
    let rotation_trace = [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        [max_u40() + one(), zero(), zero(), max_u8() + one(), zero()],
        [zero(), zero(), zero(), zero(), zero()],
    ];
    _test_rotate24(rotation_trace);
}

//   ---------- Aux ----------------------

fn _test_rotate24(rotation_trace: [[Value<Fr>; 5]; 3]) {
    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: valid_addition_trace(),
        rotation_trace_63: valid_rotation_trace_63(),
        rotation_trace_24: rotation_trace,
        xor_trace: [[Value::unknown(); 9]; 4],
    };

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn valid_rotation24_trace() -> [[Value<Fr>; 5]; 3] {
    [
        [
            max_u24(),
            max_u16(),
            known_value_from_number((1 << 8) - 1),
            zero(),
            zero(),
        ],
        [zero(), zero(), zero(), zero(), zero()],
        [
            known_value_from_number(((1u128 << 24) - 1) << 40),
            zero(),
            zero(),
            known_value_from_number(((1 << 8) - 1) << 8),
            max_u16(),
        ],
    ]
}
