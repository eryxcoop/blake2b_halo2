use super::*;

#[test]
#[should_panic(expected = "Key size must be between 1 and 64 bytes")]
fn test_blake2b_circuit_should_receive_an_key_length_less_or_equal_64() {
    let input = vec![];
    let input_size = 0;
    let key = vec![value_for(0u64); 65];
    let key_size = 65;

    let expected_output_state = [Fr::ZERO; 65];
    let circuit = Blake2bCircuit::<Fr>::new_for(input, input_size, key, key_size, 64);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}
