use halo2_proofs::dev::MockProver;
use super::*;
use crate::tests::tests_rotation::rotation_63_circuit_16bit_limbs::Rotation63Circuit16bitLimbs;

#[test]
fn test_positive_rotate_right_63() {
    let circuit = Rotation63Circuit16bitLimbs::<Fr>::new_for_trace(_valid_rotation_63_trace());
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_63() {
    let mut invalid_rotation_trace = _valid_rotation_63_trace();
    invalid_rotation_trace[0][1] = one() + invalid_rotation_trace[0][1];
    invalid_rotation_trace[0][0] = one() + invalid_rotation_trace[0][0];

    let circuit = Rotation63Circuit16bitLimbs::<Fr>::new_for_trace(invalid_rotation_trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_badly_decomposed_rotate_right_63() {
    let mut invalid_rotation_trace = _valid_rotation_63_trace();
    invalid_rotation_trace[1][2] = one();

    let circuit = Rotation63Circuit16bitLimbs::<Fr>::new_for_trace(invalid_rotation_trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn _valid_rotation_63_trace() -> [[Value<Fr>; 5]; 2] {
    [
        [one(), one(), zero(), zero(), zero()],
        [one() + one(), one() + one(), zero(), zero(), zero()],
    ]
}
