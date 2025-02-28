use std::time::Duration;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use blake2b_halo2::circuit_runner::{Blake2bCircuitInputs, CircuitRunner};
use rand::Rng;
use blake2b_halo2::auxiliar_functions::value_for;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("optimization_comparison_");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(60));

    for amount_of_blocks in [1,5,10,15,20] {
        group.throughput(Throughput::Bytes(amount_of_blocks));

        group.bench_function(
            BenchmarkId::new("A", amount_of_blocks),
            |b| b.iter_batched(
                || {
                    let ci = _random_input_for_desired_blocks(amount_of_blocks as usize);
                    let circuit = CircuitRunner::create_circuit_for_inputs_optimization_a(ci.clone());
                    (circuit, ci.4)
                },
                |(circuit, expected)| CircuitRunner::mock_prove_with_public_inputs_ref(&expected, &circuit),
                BatchSize::SmallInput
            ),
        );

        group.bench_function(
            BenchmarkId::new("B", amount_of_blocks),
            |b| b.iter_batched(
                || {
                    let ci = _random_input_for_desired_blocks(amount_of_blocks as usize);
                    let circuit = CircuitRunner::create_circuit_for_inputs_optimization_b(ci.clone());
                    (circuit, ci.4)
                },
                |(circuit, expected)| CircuitRunner::mock_prove_with_public_inputs_ref(&expected, &circuit),
                BatchSize::SmallInput
            ),
        );

        group.bench_function(
            BenchmarkId::new("C", amount_of_blocks),
            |b| b.iter_batched(
                || {
                    let ci = _random_input_for_desired_blocks(amount_of_blocks as usize);
                    let circuit = CircuitRunner::create_circuit_for_inputs_optimization_c(ci.clone());
                    (circuit, ci.4)
                },
                |(circuit, expected)| CircuitRunner::mock_prove_with_public_inputs_ref(&expected, &circuit),
                BatchSize::SmallInput
            ),
        );
    }
    group.finish()
}

fn _random_input_for_desired_blocks(
    amount_of_blocks: usize,
) -> Blake2bCircuitInputs {
    let mut rng = rand::thread_rng();

    let input_size = amount_of_blocks * 128;
    const OUTPUT_SIZE: usize = 64;
    let mut random_inputs: Vec<u8> = (0..input_size).map(|_| rng.gen_range(0..=255)).collect();
    let mut key_u8: Vec<u8> = vec![];
    let mut buffer_out = vec![0u8; OUTPUT_SIZE];

    rust_implementation::blake2b(&mut buffer_out, &mut key_u8, &mut random_inputs);

    let expected_output_: Vec<Fr> = buffer_out.iter().map(|byte| Fr::from(*byte as u64)).collect();
    let expected_output: [Fr; OUTPUT_SIZE] = expected_output_.try_into().unwrap();
    let input_values: Vec<Value<Fr>> =
        random_inputs.iter().map(|x| value_for(*x as u64)).collect();
    let key_size = 0;
    let key_values: Vec<Value<Fr>> = vec![];

    (input_values, input_size, key_values, key_size, expected_output, OUTPUT_SIZE)
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
