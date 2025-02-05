use super::*;
use crate::circuits::blake2b_circuit::Blake2bCircuit;
use halo2_proofs::dev::MockProver;

#[test]
fn test_blake2b_single_empty_block_positive() {
    let output_size = value_for(64u128);
    let input = [[zero(); 16]; 1];
    let input_size = zero();
    let expected_output_state = _correct_final_state_for_empty_input();
    let circuit = Blake2bCircuit::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_blake2b_single_empty_block_negative() {
    let output_size = value_for(64u128);
    let input = [[zero(); 16]; 1];
    let input_size = zero();
    let mut expected_output_state = _correct_final_state_for_empty_input();
    expected_output_state[7] = Fr::from(14907649232217337814u64); // Wrong value

    let circuit = Blake2bCircuit::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

fn _correct_final_state_for_empty_input() -> [Fr; 8] {
    [
        Fr::from(241225442164632184u64),   // 3590142F7026A78
        Fr::from(8273765786548291270u64),  // 72D2522585FDC6C6
        Fr::from(7009669069494759313u64),  // 614758E140472F91
        Fr::from(1825118895109998218u64),  // 19541FF717E2868A
        Fr::from(6005812539308400338u64),  // 5358EEAF31105ED2
        Fr::from(5453945543160269075u64),  // 4BB04E9344648913
        Fr::from(6176484666232027792u64),  // 55B748145B683A90
        Fr::from(14907649232217337813u64), // CEE29BFE1A706FD5
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

fn run_test<const BLOCKS: usize>(input: &String, _key: &String, expected: &String) {
    let (input_u64, input_size) = _formed_input_blocks_for::<BLOCKS>(input);
    let (expected_output_state, output_size) = _formed_output_block_for(expected);

    let input_values: [[Value<Fr>; 16]; BLOCKS] = input_u64
        .iter()
        .map(|x| x.iter().map(|y| value_for(*y)).collect::<Vec<_>>().try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let input_size_value = value_for(input_size as u128);
    let expected_output_state_fields: [Fr; 8] =
        expected_output_state.iter().map(|x| Fr::from(*x)).collect::<Vec<_>>().try_into().unwrap();
    let output_size_value = value_for(output_size as u128);

    let circuit = Blake2bCircuit::new_for(output_size_value, input_values, input_size_value);
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
        if i < 129 {
            run_test::<1>(&case.input, &case.key, &case.out);
        } else {
            run_test::<2>(&case.input, &case.key, &case.out);
        }
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
        run_test::<2>(&case.input, &case.key, &case.out);
    }
}

fn _formed_input_blocks_for<const BLOCKS: usize>(input: &String) -> ([[u64; 16]; BLOCKS], usize) {
    let input_size = input.len() / 2; // Amount of bytes
    let mut input_bytes = hex::decode(input).expect("Invalid hex string");

    input_bytes.resize(128 * BLOCKS, 0); // Fill with zeros to pad to 128*BLOCKS bytes

    let mut blocks = [[0u64; 16]; BLOCKS];
    for k in 0..BLOCKS {
        let mut current_block = [0u64; 16];
        for i in 0..16 {
            current_block[i] =
                _merge_bytes_into_64_bit_word(&(input_bytes[128 * k + 8 * i..128 * k + 8 * i + 8]))
        }
        blocks[k] = current_block;
    }

    (blocks, input_size)
}

fn _formed_output_block_for(output: &String) -> ([u64; 8], usize) {
    let mut block = [0u64; 8];
    let output_block_size = output.len() / 2; // Amount of bytes

    let output_bytes = hex::decode(output).expect("Invalid hex string");

    for i in 0..output_bytes.len() / 8 {
        let bytes = &(output_bytes[(8 * i)..(8 * i + 8)]);
        block[i] = _merge_bytes_into_64_bit_word(bytes)
    }

    (block, output_block_size)
}

fn _merge_bytes_into_64_bit_word(bytes: &[u8]) -> u64 {
    let mut word = 0u64;
    for i in 0..8 {
        word += (bytes[i] as u64) << (i * 8);
    }
    word
}
