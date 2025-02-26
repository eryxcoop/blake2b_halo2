use std::time::Duration;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use blake2b_halo2::circuit_runner::CircuitRunner;
use rand::Rng;
use blake2b_halo2::auxiliar_functions::value_for;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single optimization");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(60));

    for amount_of_blocks in 0..5 {
        group.throughput(Throughput::Bytes(amount_of_blocks));
        let (input, input_size, output_size, key_size, key,
            expected_output_state) = _random_input_for_desired_blocks(amount_of_blocks as usize);

        let circuit = CircuitRunner::create_circuit_for_inputs(input, input_size, key, key_size, output_size);
        let func = || CircuitRunner::mock_prove_with_public_inputs_ref(&expected_output_state, &circuit);

        group.bench_with_input(BenchmarkId::from_parameter(amount_of_blocks), &amount_of_blocks, |b, &_size| {
            b.iter(func)
        });
    }
    group.finish()
}

fn _random_input_for_desired_blocks(amount_of_blocks: usize) -> (Vec<Value<Fr>>, usize, usize, usize, Vec<Value<Fr>>, Vec<Fr>) {
    let mut rng = rand::thread_rng();
    let input_size = amount_of_blocks * 128;

    // Bytes for calling the Rust algorithm
    let mut random_inputs: Vec<u8> = (0..input_size).map(|_| rng.gen_range(0..=255)).collect();
    let mut key_u8: Vec<u8> = vec![];
    let mut buffer_out = vec![0u8; 1];

    rust_implementation::blake2b(&mut buffer_out, &mut key_u8, &mut random_inputs);

    // Values for calling the Halo2 algorithm
    let output_size = 1;
    let expected_output = vec![Fr::from(buffer_out[0] as u64)];
    let mut input_values: Vec<Value<Fr>> = random_inputs.iter().map(|x| value_for(*x as u64)).collect();
    let key_size = 0;
    let key_values: Vec<Value<Fr>> = vec![];

    (input_values, input_size, output_size, key_size, key_values, expected_output)
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);