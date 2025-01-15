use std::marker::PhantomData;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use crate::Blake2bCircuit;
use crate::tests::{max_u16, max_u64, one, two_power_24, two_power_8, valid_addition_trace, valid_rotation_trace, zero};

#[test]
fn test_positive_rotate_right_63() {
    let circuit = Blake2bCircuit::<Fr>::new_for_rotation_63(valid_rotation_trace());
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
    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: valid_addition_trace(),
        rotation_trace_64: valid_rotation_trace(),
        // TODO chequear traza y despues hacer otro test mas complejo
        rotation_trace_24: [
            [Value::known(Fr::from(((1u128 << 24) - 1) as u64)), max_u16(), Value::known(Fr::from((1 << 8) - 1)), zero(), zero()],
            [zero(), zero(), zero(), zero(), zero()],
            [Value::known(Fr::from((((1u128 << 24) - 1) * (1u128 << 40)) as u64)), zero(), zero(), Value::known(Fr::from(((1 << 8) - 1) * (1 << 8))), max_u16()],
        ],
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_rotate_right_24_b() {
    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: valid_addition_trace(),
        rotation_trace_64: valid_rotation_trace(),
        // TODO chequear traza y despues hacer otro test mas complejo
        rotation_trace_24: [
            [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
            [Value::known(Fr::from(((1u128 << 40) - 1) as u64)), max_u16(), max_u16(), Value::known(Fr::from(((1 << 8) - 1))), zero()],
            [max_u64(), max_u16(), max_u16(), max_u16(), max_u16()],
        ],
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

