use crate::auxiliar_functions::{generate_row_8bits, value_for, zero};
use crate::tests::tests_addition::addition_mod_64_circuit_8bits::AdditionMod64Circuit8Bits;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;

#[test]
fn test_positive_addition_with_0() {
    // This value is used to assigned in cells where the value is not relevant for the circuit
    // it is zero, but it could be any value
    let unconstrained_value = zero();
    let trace = [
        [zero(), zero(), zero(), zero(), zero(), zero(), zero(), zero(), zero()],
        [value_for(42u64), zero(), unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value],
        [value_for(42u64), value_for(42u64), zero(), zero(), zero(), zero(), zero(), zero(), zero()],
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let trace = [
        [value_for(42u64), zero(), zero(), zero(), zero(), zero(), zero(), zero(), zero()],
        [zero(), zero(), unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value, unconstrained_value],
        [value_for(42u64), value_for(42u64), zero(), zero(), zero(), zero(), zero(), zero(), zero()],
    ];
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

    let trace = [generate_row_8bits::<u64, Fr>(0); 3];
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
    let x: u128 = rng.gen();
    let max_u64 = (1u128 << 64) - 1;
    let trace = [
        generate_row_8bits::<u128, Fr>(x),
        generate_row_8bits::<u128, Fr>(max_u64),
        generate_row_8bits::<u128, Fr>(x + max_u64),
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
    trace[1][1] = value_for(1u8);
    let circuit = AdditionMod64Circuit8Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_sum_correct_but_decomposition_exceedes_range_check() {
    // This should panic because, although the sum is correct,
    // the result does not respect the max sizes
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
