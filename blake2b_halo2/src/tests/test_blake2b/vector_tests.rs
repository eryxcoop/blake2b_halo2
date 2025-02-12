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

pub fn run_test(input: &String, key: &String, expected: &String) {
    // INPUT
    let input_size = input.len() / 2; // Amount of bytes
    let input_bytes = hex::decode(input).expect("Invalid hex string");
    let input_values =
        input_bytes.iter().map(|x| Value::known(Fr::from(*x as u64))).collect::<Vec<_>>();

    // OUTPUT
    let (expected_output, output_size) = formed_output_block_for(expected);
    let expected_output_fields: [Fr; 64] =
        expected_output.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<_>>().try_into().unwrap();

    // KEY
    let key_size = key.len() / 2; // Amount of bytes
    let key_bytes = hex::decode(key).expect("Invalid hex string");
    let key_values =
        key_bytes.iter().map(|x| Value::known(Fr::from(*x as u64))).collect::<Vec<_>>();

    // TEST
    let circuit =
        Blake2bCircuit::<Fr>::new_for(input_values, input_size, key_values, key_size, output_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_fields.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_hashes_in_circuit_one_block() {
    let file_content = std::fs::read_to_string("../rust_implementation/test_vector.json")
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
    let file_content = std::fs::read_to_string("../rust_implementation/test_vector.json")
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

#[test]
fn test_hashes_in_circuit_with_key() {
    let file_content = std::fs::read_to_string("../rust_implementation/test_vector.json")
        .expect("Failed to read file");
    let test_cases: Vec<TestCase> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");

    for (i, case) in test_cases.iter().enumerate() {
        if case.key.is_empty() {
            continue;
        }

        // Uncomment to run representative test cases of edge cases
        // if i != 256 && i != 257 && i != 384 && i != 385 {
        //     continue;
        // }

        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

pub fn formed_output_block_for(output: &String) -> ([u8; 64], usize) {
    let output_block_size = output.len() / 2; // Amount of bytes
    let output_bytes = hex::decode(output).expect("Invalid hex string");
    (output_bytes.try_into().unwrap(), output_block_size)
}
