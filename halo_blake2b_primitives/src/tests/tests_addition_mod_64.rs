use crate::tests::{max_u16, max_u64, one, valid_addition_trace, zero};
use crate::Blake2bCircuit;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;

#[test]
fn test_positive_addition() {
    let trace = valid_addition_trace();

    let circuit = Blake2bCircuit::<Fr>::new_for_addition_alone(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_wrong_sum() {
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

    let circuit = Blake2bCircuit::<Fr>::new_for_addition_alone(trace);
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

    let circuit = Blake2bCircuit::<Fr>::new_for_addition_alone(trace);
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

    let circuit = Blake2bCircuit::<Fr>::new_for_addition_alone(trace);
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

    let circuit = Blake2bCircuit::<Fr>::new_for_addition_alone(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
