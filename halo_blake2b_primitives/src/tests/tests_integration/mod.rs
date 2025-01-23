mod xxx_circuit;

use crate::tests::tests_integration::xxx_circuit::XXXCircuit;
use super::*;

#[test]
fn test_xxx(){
    // ((A + B) xor C) rot63 rot16 rot24 rot32 = D
    let a = zero();
    let b = max_u64();
    let c = max_u64();
    let expected_result = zero();

    let circuit = XXXCircuit::<Fr>::new_for(a, b, c, expected_result);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}