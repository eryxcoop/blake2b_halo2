use criterion::{BenchmarkGroup, SamplingMode};
use criterion::measurement::WallTime;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use blake2b_halo2::auxiliar_functions::value_for;
use blake2b_halo2::blake2b::circuit_runner::Blake2bCircuitInputs;

pub fn benchmarking_block_sizes() -> Vec<usize> {
    vec![1, 5, 10, 20, 30]
}

pub fn sample_size() -> usize {
    30
}

pub fn configure_group(group: &mut BenchmarkGroup<WallTime>) {
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(sample_size());
    //group.measurement_time(Duration::from_secs(1000));
}

pub fn random_input_for_desired_blocks(amount_of_blocks: usize) -> Blake2bCircuitInputs {
    let mut rng = rand::thread_rng();

    let input_size = amount_of_blocks * 128;
    const OUTPUT_SIZE: usize = 64;
    let mut random_inputs: Vec<u8> = (0..input_size).map(|_| rng.gen_range(0..=255)).collect();
    let mut key_u8: Vec<u8> = vec![];
    let mut buffer_out = vec![0u8; OUTPUT_SIZE];

    rust_implementation::blake2b(&mut buffer_out, &mut key_u8, &mut random_inputs);

    let expected_output_: Vec<Fr> = buffer_out.iter().map(|byte| Fr::from(*byte as u64)).collect();
    let expected_output: [Fr; OUTPUT_SIZE] = expected_output_.try_into().unwrap();
    let input_values: Vec<Value<Fr>> = random_inputs.iter().map(|x| value_for(*x as u64)).collect();
    let key_size = 0;
    let key_values: Vec<Value<Fr>> = vec![];

    (input_values, input_size, key_values, key_size, expected_output, OUTPUT_SIZE)
}
