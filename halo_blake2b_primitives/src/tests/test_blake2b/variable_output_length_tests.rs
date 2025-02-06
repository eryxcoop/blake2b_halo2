use super::*;

#[test]
fn test_blake2b_circuit_can_verify_an_output_of_length_1(){
    const OUTPUT_SIZE: usize = 1;
    let input = [[zero(); 16]; 1];
    let input_size = zero();
    let expected_output_state = _correct_output_for_empty_input_1();
    let circuit = Blake2bCircuit::<Fr, 1, OUTPUT_SIZE>::new_for(input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_blake2b_circuit_can_verify_an_output_of_length_1_negative(){
    const OUTPUT_SIZE: usize = 1;
    let input = [[zero(); 16]; 1];
    let input_size = zero();
    let mut expected_output_state = _correct_output_for_empty_input_1();
    expected_output_state[0] = Fr::from(14u64); // Wrong value
    let circuit = Blake2bCircuit::<Fr, 1, OUTPUT_SIZE>::new_for(input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_blake2b_circuit_can_verify_an_output_of_length_32(){
    const OUTPUT_SIZE: usize = 32;
    let input = [[zero(); 16]; 1];
    let input_size = zero();
    let expected_output_state = _correct_output_for_empty_input_32();
    let circuit = Blake2bCircuit::<Fr, 1, OUTPUT_SIZE>::new_for(input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_blake2b_circuit_can_verify_an_output_of_length_32_negative(){
    const OUTPUT_SIZE: usize = 32;
    let input = [[zero(); 16]; 1];
    let input_size = zero();
    let mut expected_output_state = _correct_output_for_empty_input_32();
    expected_output_state[0] = Fr::from(15u64); // Wrong value
    let circuit = Blake2bCircuit::<Fr, 1, OUTPUT_SIZE>::new_for(input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

fn _correct_output_for_empty_input_1() -> [Fr; 1] {
    [Fr::from(46)]
}

fn _correct_output_for_empty_input_32() -> [Fr; 32] {
    [
        14, 87, 81, 192, 38, 229, 67, 178, 232, 171, 46,
        176, 96, 153, 218, 161, 209, 229, 223, 71,
        119, 143, 119, 135, 250, 171, 69, 205, 241, 47, 227, 168
    ].iter().map(|x| Fr::from(*x as u64)).collect::<Vec<_>>().try_into().unwrap()
}