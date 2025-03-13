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

#[test]
fn test_hashes() {
    let file_content = std::fs::read_to_string("../test_vector.json").expect("Failed to read file");
    let test_cases: Vec<TestCase> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");

    for (i, case) in test_cases.iter().enumerate() {
        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

fn run_test(input: &str, key: &str, expected: &str) {
    let mut input_message = hex_to_bytes(input);
    let mut key = hex_to_bytes(key);
    let expected_out = hex_to_bytes(expected);
    let mut buffer_out: Vec<u8> = Vec::new();
    buffer_out.resize(expected_out.len(), 0);

    blake2b(&mut buffer_out, &mut key, &mut input_message);

    assert_eq!(
        buffer_out, expected_out,
        "Test failed for input: {:?}, key: {:?}",
        input, key
    );
}
