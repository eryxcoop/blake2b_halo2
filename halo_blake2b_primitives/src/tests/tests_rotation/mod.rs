mod limb_rotation_circuit;
mod rotation_24_ciruit;
mod rotation_63_circuit;

use super::*;
use crate::tests::tests_rotation::limb_rotation_circuit::LimbRotationCircuit;
use crate::tests::tests_rotation::rotation_24_ciruit::Rotation24Circuit;
use crate::tests::tests_rotation::rotation_63_circuit::Rotation63Circuit;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;

// ------------ ROTATION 63 ------------ //

#[test]
fn test_positive_rotate_right_63() {
    let circuit = Rotation63Circuit::<Fr>::new_for_trace(_valid_rotation_63_trace());
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

    let circuit = Rotation63Circuit::<Fr>::new_for_trace(invalid_rotation_trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_badly_decomposed_rotate_right_63() {
    let mut invalid_rotation_trace = _valid_rotation_63_trace();
    invalid_rotation_trace[1][2] = one();

    let circuit = Rotation63Circuit::<Fr>::new_for_trace(invalid_rotation_trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

// ------------ ROTATION 24 ------------ //

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

// ------------ ROTATION 32 ------------ //

#[test]
fn test_positive_rotate_right_32() {
    let first_row: [Value<Fr>; 9] = generate_row_8bits((1u64 << 32) - 1u64)[0..9]
        .try_into()
        .unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits((1u128 << 64) - (1u128 << 32))[0..9]
        .try_into()
        .unwrap();
    let valid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 32>::new_for_trace(valid_rotation_32_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let valid_rotation_32_trace = [second_row, first_row];

    let circuit = LimbRotationCircuit::<Fr, 32>::new_for_trace(valid_rotation_32_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_random_rotate_right_32() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let pow32 = 1u64 << 32;
    let expected_result = ((n % pow32) << 32) + (n / pow32);
    let first_row: [Value<Fr>; 9] = generate_row_8bits(n)[0..9]
        .try_into()
        .unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(expected_result)[0..9]
        .try_into()
        .unwrap();
    let valid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 32>::new_for_trace(valid_rotation_32_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_32() {
    let first_row: [Value<Fr>; 9] = generate_row_8bits((1u64 << 32) - 1u64)[0..9]
        .try_into()
        .unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits((1u128 << 64) - 1)[0..9]
        .try_into()
        .unwrap();
    let invalid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 32>::new_for_trace(invalid_rotation_32_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

// ------------ ROTATION 24 ------------ //
#[test]
fn test_positive_rotate_right_24_limbs() {
    let first_row: [Value<Fr>; 9] = generate_row_8bits(1u128 << 24)[0..9].try_into().unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(1u128)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 24>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_random_rotate_right_24() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let pow24 = 1u64 << 24;
    let expected_result = ((n % pow24) << 40) + (n / pow24);
    let first_row: [Value<Fr>; 9] = generate_row_8bits(n)[0..9]
        .try_into()
        .unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(expected_result)[0..9]
        .try_into()
        .unwrap();
    let valid_rotation_24_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 24>::new_for_trace(valid_rotation_24_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_24_limbs() {
    let first_row: [Value<Fr>; 9] = generate_row_8bits(1u128 << 24)[0..9].try_into().unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(2u8)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 24>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

// ------------ ROTATION 16 ------------ //
#[test]
fn test_positive_rotate_right_16_limbs() {
    let first_row: [Value<Fr>; 9] = generate_row_8bits(1u128 << 16)[0..9].try_into().unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(1u128)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 16>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_random_rotate_right_16() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let pow16 = 1u64 << 16;
    let expected_result = ((n % pow16) << 48) + (n / pow16);
    let first_row: [Value<Fr>; 9] = generate_row_8bits(n)[0..9]
        .try_into()
        .unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(expected_result)[0..9]
        .try_into()
        .unwrap();
    let valid_rotation_16_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 16>::new_for_trace(valid_rotation_16_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_16_limbs() {
    let first_row: [Value<Fr>; 9] = generate_row_8bits(1u128 << 16)[0..9].try_into().unwrap();
    let second_row: [Value<Fr>; 9] = generate_row_8bits(2u8)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fr, 16>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

// ------------ AUX ------------ //

fn _valid_rotation24_trace() -> [[Value<Fr>; 5]; 3] {
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

fn _valid_rotation_63_trace() -> [[Value<Fr>; 5]; 2] {
    [
        [one(), one(), zero(), zero(), zero()],
        [one() + one(), one() + one(), zero(), zero(), zero()],
    ]
}
