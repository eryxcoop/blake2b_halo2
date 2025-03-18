use crate::auxiliar_functions::{generate_row_8bits, value_for};
use crate::tests::tests_addition::addition_mod_64_circuit_8bits::AdditionMod64Circuit8Bits;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;

#[test]
fn test_positive_addition_with_0() {
    let mut rng = rand::thread_rng();
    let random_u64: u64 = rng.gen();
    let trace = [
        generate_row_8bits::<u64, Fr>(0),
        generate_row_8bits::<u64, Fr>(random_u64),
        generate_row_8bits::<u64, Fr>(random_u64),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let random_u64: u64 = rng.gen();
    let trace = [
        generate_row_8bits::<u64, Fr>(random_u64),
        generate_row_8bits::<u64, Fr>(0),
        generate_row_8bits::<u64, Fr>(random_u64),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let trace = [
        generate_row_8bits::<u64, Fr>(0),
        generate_row_8bits::<u64, Fr>(0),
        generate_row_8bits::<u64, Fr>(0),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_without_carry() {
    let trace = [
        generate_row_8bits::<u64, Fr>(1),
        generate_row_8bits::<u64, Fr>(1),
        generate_row_8bits::<u64, Fr>(2),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let trace = [
        generate_row_8bits::<u128, Fr>((1u128 << 63) - 1),
        generate_row_8bits::<u64, Fr>(1),
        generate_row_8bits::<u128, Fr>(1u128 << 63),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let mut rng = rand::thread_rng();
    let mut n1: u64 = rng.gen();
    let mut n2: u64 = rng.gen();
    if n2 < n1 {
        // We want n1 < n2
        std::mem::swap(&mut n1, &mut n2);
    }
    let trace = [
        generate_row_8bits::<u64, Fr>(n1),
        generate_row_8bits::<u64, Fr>(n2 - n1),
        generate_row_8bits::<u64, Fr>(n2),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_with_carry() {
    let mut rng = rand::thread_rng();
    let x: u64 = rng.gen();
    let mut trace = [
        generate_row_8bits::<u64, Fr>(x),
        generate_row_8bits::<u128, Fr>((1u128 << 64) - 1),
        generate_row_8bits::<u64, Fr>(x - 1),
    ];
    trace[2][9] = value_for(1u8);
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let mut trace = [
        generate_row_8bits::<u128, Fr>(1u128 << 63),
        generate_row_8bits::<u128, Fr>((1u128 << 63) + (1u128 << 27)),
        generate_row_8bits::<u128, Fr>(1u128 << 27),
    ];
    trace[2][9] = value_for(1u8);
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_addition() {
    let trace = [
        generate_row_8bits::<u64, Fr>(1),
        generate_row_8bits::<u64, Fr>(1),
        generate_row_8bits::<u64, Fr>(3),
    ];

    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_random_addition() {
    let mut rng = rand::thread_rng();
    let trace = [
        generate_row_8bits::<u64, Fr>(rng.gen()),
        generate_row_8bits::<u64, Fr>(rng.gen()),
        generate_row_8bits::<u64, Fr>(rng.gen()),
    ];

    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_sum_correct_but_no_carry_tracked() {
    // This should panic because, although the sum is correct, the carry column is not computed. It should be 1.
    let mut rng = rand::thread_rng();
    let x: u64 = rng.gen();
    let trace = [
        generate_row_8bits::<u64, Fr>(x),
        generate_row_8bits::<u128, Fr>((1u128 << 64) - 1),
        generate_row_8bits::<u64, Fr>(x - 1),
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_sum_correct_but_unnecessary_carry() {
    // This should panic because, although the sum is correct, the carry column is incorrect. It should be 0.
    let mut trace = [
        generate_row_8bits::<u64, Fr>(1),
        generate_row_8bits::<u128, Fr>(2),
        generate_row_8bits::<u64, Fr>(3),
    ];
    trace[2][9] = value_for(1u8);
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_sum_correct_but_decomposition_exceedes_range_check() {
    // This should panic because, although the sum is correct and the decomposition adds up,
    // the decomposition does not respect the max sizes
    let mut trace = [
        generate_row_8bits::<u64, Fr>(1 << 8),
        generate_row_8bits::<u128, Fr>((1 << 8) - 1),
        generate_row_8bits::<u64, Fr>((1 << 9) - 1),
    ];
    trace[0][1] = value_for(1u16 << 8);
    trace[0][2] = value_for(0u8);
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
