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
    let (input_values, input_size, key_values, key_size, expected_output_fields, output_size) =
        prepare_parameters_for_test(input, key, expected);

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
