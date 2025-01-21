use super::*;
use crate::Blake2bCircuit;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;

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
    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_24(rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_rotate_right_24_b() {
    let rotation_trace = [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        [max_u40(), max_u16(), max_u16(), max_u8(), zero()],
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
    ];
    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_24(rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_24() {
    let rotation_trace = [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        [max_u40(), max_u16(), max_u16(), max_u8(), zero()],
        [one(), one(), zero(), zero(), zero()],
    ];
    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_24(rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_rotate_right_24_chunk_out_of_range() {
    let rotation_trace = [
        [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        [max_u40() + one(), zero(), zero(), max_u8() + one(), zero()],
        [zero(), zero(), zero(), zero(), zero()],
    ];
    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_24(rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

//   ---------- Aux ----------------------

fn valid_rotation24_trace() -> [[Value<Fr>; 5]; 3] {
    [
        [
            max_u24(),
            max_u16(),
            value_for((1u64 << 8) - 1),
            zero(),
            zero(),
        ],
        [zero(), zero(), zero(), zero(), zero()],
        [
            value_for(((1u128 << 24) - 1) << 40),
            zero(),
            zero(),
            value_for(((1u64 << 8) - 1) << 8),
            max_u16(),
        ],
    ]
}
