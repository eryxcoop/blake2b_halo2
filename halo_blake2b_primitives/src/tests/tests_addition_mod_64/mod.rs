mod addition_mod_64_circuit_16bits;

use super::*;
use crate::tests::tests_addition_mod_64::addition_mod_64_circuit_16bits::AdditionMod64Circuit16Bits;
use halo2_proofs::dev::MockProver;

#[test]
fn test_positive_addition() {
    let circuit = AdditionMod64Circuit16Bits::<Fr>::new_for_trace(_valid_addition_trace());
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_wrong_sum_with_overflow() {
    let trace = [
        [
            max_u64(),
            max_u16(),
            max_u16(),
            max_u16(),
            max_u16(),
            zero(),
        ],
        [one(), one(), zero(), zero(), zero(), zero()],
        [one(), one(), zero(), zero(), zero(), one()],
    ];

    let circuit = AdditionMod64Circuit16Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_wrong_decomposition() {
    let trace = [
        [
            max_u64(),
            max_u16(),
            max_u16(),
            max_u16(),
            max_u16(),
            zero(),
        ],
        [zero(), zero(), zero(), zero(), zero(), zero()],
        [max_u64(), max_u16(), max_u16(), one(), max_u16(), zero()],
    ];

    let circuit = AdditionMod64Circuit16Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_wrong_carry() {
    let trace = [
        [
            max_u64(),
            max_u16(),
            max_u16(),
            max_u16(),
            max_u16(),
            zero(),
        ],
        [one(), one(), zero(), zero(), zero(), zero()],
        [zero(), zero(), zero(), zero(), zero(), one() + one()],
    ];

    let circuit = AdditionMod64Circuit16Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_wrong_rangecheck() {
    let trace = [
        [
            max_u16() + one(),
            max_u16() + one(),
            zero(),
            zero(),
            zero(),
            zero(),
        ],
        [zero(), zero(), zero(), zero(), zero(), zero()],
        [max_u16() + one(), zero(), one(), zero(), zero(), zero()],
    ];

    let circuit = AdditionMod64Circuit16Bits::<Fr>::new_for_trace(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn _valid_addition_trace() -> [[Value<Fr>; 6]; 3] {
    [
        [
            max_u64(),
            max_u16(),
            max_u16(),
            max_u16(),
            max_u16(),
            zero(),
        ],
        [one(), one(), zero(), zero(), zero(), zero()],
        [zero(), zero(), zero(), zero(), zero(), one()],
    ]
}
