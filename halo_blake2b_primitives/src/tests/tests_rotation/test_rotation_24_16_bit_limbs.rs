use super::*;
use crate::tests::tests_rotation::rotation_24_ciruit::Rotation24Circuit;
use halo2_proofs::dev::MockProver;

#[test]
fn test_positive_rotate_right_24() {
    let rotation_trace = _valid_rotation24_trace();
    let circuit = Rotation24Circuit::<Fr>::new_for_trace(rotation_trace);

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
    let circuit = Rotation24Circuit::<Fr>::new_for_trace(rotation_trace);

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
    let circuit = Rotation24Circuit::<Fr>::new_for_trace(rotation_trace);

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
    let circuit = Rotation24Circuit::<Fr>::new_for_trace(rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn _valid_rotation24_trace() -> [[Value<Fr>; 5]; 3] {
    [
        [max_u24(), max_u16(), value_for((1u64 << 8) - 1), zero(), zero()],
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
