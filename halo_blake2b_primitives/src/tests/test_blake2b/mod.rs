mod blake2b_ciruit_short;

use super::*;
use crate::tests::test_blake2b::blake2b_ciruit_short::Blake2bCircuitShort;
use halo2_proofs::dev::MockProver;


#[test]
fn test_blake2b_single_empty_block_positive() {
    let output_size = value_for(64u128);
    let input = [zero(); 16];
    let input_size = zero();
    let expected_output_state = _correct_final_state_for_empty_input();
    let circuit = Blake2bCircuitShort::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_blake2b_single_empty_block_negative() {
    let output_size = value_for(64u128);
    let input = [zero(); 16];
    let input_size = zero();
    let mut expected_output_state = _correct_final_state_for_empty_input();
    expected_output_state[7] = Fr::from(14907649232217337814u64); // Wrong value

    let circuit = Blake2bCircuitShort::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

fn _correct_final_state_for_empty_input() -> [Fr; 8] {
    [
        Fr::from(241225442164632184u64),
        Fr::from(8273765786548291270u64),
        Fr::from(7009669069494759313u64),
        Fr::from(1825118895109998218u64),
        Fr::from(6005812539308400338u64),
        Fr::from(5453945543160269075u64),
        Fr::from(6176484666232027792u64),
        Fr::from(14907649232217337813u64),
    ]
}

// ---------------------------- Test vectors from the Rust implementation ----------------------------

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
    let (input, input_size) = _formed_input_block_for::<16>(input);
    let (expected_output_state, output_size) = _formed_input_block_for::<8>(expected);

    let input_values: [Value<Fr>; 16] = input.iter().map(|x| value_for(*x)).collect::<Vec<_>>().try_into().unwrap();
    let input_size_value = value_for(input_size as u128);
    let expected_output_state_fields: [Fr; 16] = expected_output_state.iter().map(|x| Fr::from(*x)).collect::<Vec<_>>().try_into().unwrap();
    let output_size_value = value_for(output_size as u128);

    let circuit = Blake2bCircuitShort::new_for(output_size_value, input_values, input_size_value);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state_fields.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_hashes_in_circuit() {
    let file_content =
        std::fs::read_to_string("../blake2b_implementation_rust/test_vector.json").expect("Failed to read file");
    let test_cases: Vec<TestCase> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");

    for (i, case) in test_cases.iter().enumerate() {
        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

fn _formed_input_block_for<const T: usize>(input: &String) -> ([u64; T], usize) {
    let mut block = [0u64; T];
    let input_block_size = input.len()/2; // Amount of bytes

    let mut input_bytes = hex::decode(input).expect("Invalid hex string");
    input_bytes.resize(T*8, 0); // Fill with zeros to pad to 64/128 bytes

    for i in 0..input_bytes.len() / 8 {
        block[i] = _merge_bytes_into_64_bit_word(&(input_bytes[8*i..8*i+8]))
    }

    (block, input_block_size)
}

fn _merge_bytes_into_64_bit_word(bytes: &[u8]) -> u64 {
    let mut word = 0u64;
    for i in 0..8 {
        word = word + (bytes[i] as u64) << (i * 8);
    }
    word
}
