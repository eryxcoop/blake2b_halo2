use blake2b_halo2::chips::blake2b_implementations::blake2b_chip::Blake2bChip;
use blake2b_halo2::circuits::blake2b_circuit::Blake2bCircuit;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::cost_model::{from_circuit_to_cost_model_options, CostOptions};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::Deserialize;
use std::cmp::max;

#[derive(Deserialize, Debug)]
struct Blake2bInput {
    #[serde(rename = "in")]
    input: String,
    key: String,
    output_size: usize,
}

fn main() {
    let workspace_root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let file_path = format!("{}/interface/src/inputs.json", workspace_root);

    let file_content = std::fs::read_to_string(file_path).expect("Failed to read input file");
    let input: Blake2bInput = serde_json::from_str(&file_content).expect("Failed to parse input");

    let (input, key, buffer_out) = run_blake2b(&input.input, &input.key, input.output_size);
    println!("Hash digest bytes: {:?}\n\n", buffer_out);
    println!("The amount of bytes in your input is {}", input.len());
    println!("The amount of bytes in your key is {}", key.len());
    println!(
        "The amount of blocks processed by the hash is {}",
        amount_of_blocks(&input, &key)
    );
    println!(
        "The amount of rows in the circuit depends only on the amount of blocks, so two inputs \
    of different sizes but same amount of blocks will have same length in the circuit\n\n"
    );
    println!("Computing the circuit and generating the proof, this could take a couple of seconds ...\n\n");
    let cost_options = run_blake2b_halo2(input.clone(), key.clone(), buffer_out);
    println!("Cost model options: ");
    println!(
        "The amount of advice rows is {} (for {} blocks of input)",
        cost_options.rows_count,
        amount_of_blocks(&input, &key)
    );
    println!(
        "The amount of advice columns is {}",
        cost_options.advice.len()
    );
    println!(
        "The amount of instance columns is {}",
        cost_options.instance.len()
    );
    println!(
        "The amount of fixed columns is {}",
        cost_options.fixed.len()
    );
    println!("The gate degree is {}", cost_options.gate_degree);
    println!("The max degree is {}", cost_options.max_degree);
    println!("The table rows count is {}", cost_options.table_rows_count);
    println!(
        "The compressed rows count is {}",
        cost_options.compressed_rows_count
    );
}

fn run_blake2b(input: &str, key: &str, output_size: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut input_message = rust_implementation::hex_to_bytes(input);
    let mut key = rust_implementation::hex_to_bytes(key);
    let mut buffer_out: Vec<u8> = vec![0; output_size];

    rust_implementation::blake2b(&mut buffer_out, &mut key, &mut input_message);
    (input_message, key, buffer_out)
}

fn run_blake2b_halo2(
    input_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
    expected_output: Vec<u8>,
) -> CostOptions {
    // INPUT
    let input_size = input_bytes.len();
    let input_values = input_bytes
        .iter()
        .map(|x| Value::known(Fr::from(*x as u64)))
        .collect::<Vec<_>>();

    // OUTPUT
    let output_size = expected_output.len();
    let expected_output_fields: Vec<Fr> = expected_output
        .iter()
        .map(|x| Fr::from(*x as u64))
        .collect::<Vec<_>>();

    // KEY
    let key_size = key_bytes.len();
    let key_values = key_bytes
        .iter()
        .map(|x| Value::known(Fr::from(*x as u64)))
        .collect::<Vec<_>>();

    // TEST
    let circuit = Blake2bCircuit::<Fr, Blake2bChip<Fr>>::new_for(
        input_values,
        input_size,
        key_values,
        key_size,
        output_size,
    );

    let k = compute_k(amount_of_blocks(&input_bytes, &key_bytes));
    let options = from_circuit_to_cost_model_options(Some(k), &circuit, 1);
    let prover = MockProver::run(k, &circuit, vec![expected_output_fields]).unwrap();
    prover.verify().unwrap();

    options
}

fn compute_k(amount_of_blocks: usize) -> u32 {
    let value = max(1 << 17, 3735_u32.saturating_mul(amount_of_blocks as u32));
    f64::from(value).log2().ceil() as u32
}

fn amount_of_blocks(input: &[u8], key: &[u8]) -> usize {
    if key.is_empty() {
        (input.len() as f64 / 128f64).ceil() as usize
    } else if input.is_empty() {
        1
    } else {
        input.len() / 128 + 1
    }
}
