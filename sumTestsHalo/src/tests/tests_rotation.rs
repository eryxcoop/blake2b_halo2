use std::marker::PhantomData;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use crate::Blake2bCircuit;
use crate::tests::{one, valid_addition_trace, valid_rotation_trace};

#[test]
fn test_positive_rotate_right_63() {
    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: valid_addition_trace(),
        rotation_trace: valid_rotation_trace(),
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_63() {
    let mut invalid_rotation_trace = valid_rotation_trace();
    invalid_rotation_trace[0][1] = one() + invalid_rotation_trace[0][1];
    invalid_rotation_trace[0][0] = one() + invalid_rotation_trace[0][0];

    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: valid_addition_trace(),
        rotation_trace: invalid_rotation_trace,
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}