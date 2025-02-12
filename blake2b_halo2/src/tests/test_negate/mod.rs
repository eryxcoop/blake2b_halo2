use super::*;
mod negate_circuit;

use crate::auxiliar_functions::{max_u64, zero};
use crate::tests::test_negate::negate_circuit::NegateCircuit;
use halo2_proofs::dev::MockProver;

#[test]
fn test_negate_zero_should_result_in_max_number() {
    let x = zero();
    let not_x = max_u64();

    let circuit = NegateCircuit::new_for(x, not_x);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_negate_number_should_result_in_max_number_minus_that_number() {
    let number = (1u128 << 40) - 1;
    let max_number = (1u128 << 64) - 1;
    let not_x: Value<Fr> = value_for(max_number - number);

    let circuit = NegateCircuit::new_for(value_for(number), not_x);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negate_number_fails_when_given_a_wrong_result() {
    let number = (1u128 << 40) - 1;
    let max_number = (1u128 << 64) - 1;
    let not_x: Value<Fr> = value_for(max_number - number - 1);

    let circuit = NegateCircuit::new_for(value_for(number), not_x);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
