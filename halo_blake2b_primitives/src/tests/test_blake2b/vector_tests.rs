use super::*;

use serde::Deserialize;
use serde_json;

#[derive(Deserialize, Debug)]
struct TestCase {
    #[serde(rename = "in")]
    input: String,
    key: String,
    out: String,
}

fn run_test(input: &String, _key: &String, expected: &String) {
    let input_size = input.len() / 2; // Amount of bytes
    let input_bytes = hex::decode(input).expect("Invalid hex string");
    let input_values =
        input_bytes.iter().map(|x| Value::known(Fr::from(*x as u64))).collect::<Vec<_>>();
    let (expected_output_state, _output_size) = _formed_output_block_for(expected);

    let expected_output_state_fields: [Fr; 64] = expected_output_state
        .iter()
        .map(|x| Fr::from(*x as u64))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let circuit = Blake2bCircuit::<Fr>::new_for(input_values, input_size, 64);
    let prover =
        MockProver::run(17, &circuit, vec![expected_output_state_fields.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_hashes_in_circuit_one_block() {
    let file_content = std::fs::read_to_string("../blake2b_implementation_rust/test_vector.json")
        .expect("Failed to read file");
    let test_cases: Vec<TestCase> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");

    for (i, case) in test_cases.iter().enumerate() {
        // Empty key and single block for now
        if !case.key.is_empty() || case.input.len() > 256 {
            continue;
        }

        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

#[test]
fn test_hashes_in_circuit_more_than_one_block() {
    let file_content = std::fs::read_to_string("../blake2b_implementation_rust/test_vector.json")
        .expect("Failed to read file");
    let test_cases: Vec<TestCase> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");

    for (i, case) in test_cases.iter().enumerate() {
        if !case.key.is_empty() || case.input.len() <= 256 {
            continue;
        }

        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

fn _formed_output_block_for(output: &String) -> ([u8; 64], usize) {
    let output_block_size = output.len() / 2; // Amount of bytes

    let output_bytes = hex::decode(output).expect("Invalid hex string");

    (output_bytes.try_into().unwrap(), output_block_size)
}

fn _merge_bytes_into_64_bit_word(bytes: &[u8]) -> u64 {
    let mut word = 0u64;
    for i in 0..8 {
        word += (bytes[i] as u64) << (i * 8);
    }
    word
}
