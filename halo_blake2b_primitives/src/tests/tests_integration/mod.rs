mod many_operations_circuit;

use crate::tests::tests_integration::many_operations_circuit::ManyOperationsCircuit;
use super::*;

#[test]
fn test_positive_chained_operations(){
    // ((A + B) xor C) rot63 rot16 rot24 rot32 = D
    let a = zero();
    let b = max_u64();
    let c = max_u64();
    let expected_result = zero();

    _test_many_operations(a, b, c, expected_result);
}

#[test]
#[should_panic]
fn test_negative_chained_operations(){
    // ((A + B) xor C) rot63 rot16 rot24 rot32 = D
    let a = zero();
    let b = max_u64();
    let c = max_u64();
    let expected_result_wrong = one();

    _test_many_operations(a, b, c, expected_result_wrong);
}

#[test]
fn test_positive_chained_operations_2(){
    // ((A + B) xor C) rot63 rot16 rot24 rot32 = D
    let a = max_u32();
    let b = max_u64() - max_u32();
    let c = max_u64() - one(); // 1
    let expected_result = value_for(1u128 << 57);

    _test_many_operations(a, b, c, expected_result);
}

fn _test_many_operations(a: Value<Fr>, b: Value<Fr>, c: Value<Fr>, expected_result: Value<Fr>) {
    let circuit = ManyOperationsCircuit::<Fr>::new_for(a, b, c, expected_result);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}