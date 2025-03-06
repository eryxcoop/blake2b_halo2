use std::time::Duration;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use criterion::measurement::WallTime;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use blake2b_halo2::circuit_runner::{Blake2bCircuitInputs, CircuitRunner};
use rand::Rng;
use blake2b_halo2::auxiliar_functions::value_for;
use blake2b_halo2::chips::blake2b_implementations::blake2b_chip_opt_4_limbs::Blake2bChipOpt4Limbs;
use blake2b_halo2::chips::blake2b_implementations::blake2b_chip_opt_recycle::Blake2bChipOptRecycle;
use blake2b_halo2::chips::blake2b_implementations::blake2b_chip_opt_spread::Blake2bChipOptSpread;
use blake2b_halo2::chips::blake2b_implementations::blake2b_instructions::Blake2bInstructions;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("optimization_comparison");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(60));

    for amount_of_blocks in [1usize,5,10,15,20] {
        group.throughput(Throughput::Bytes(amount_of_blocks as u64));

        benchmark_optimization_with_amount_of_blocks::<Blake2bChipOpt4Limbs<Fr>>(&mut group, amount_of_blocks, "opt_4_limbs");
        benchmark_optimization_with_amount_of_blocks::<Blake2bChipOptRecycle<Fr>>(&mut group, amount_of_blocks, "opt_recycle");
        benchmark_optimization_with_amount_of_blocks::<Blake2bChipOptSpread<Fr>>(&mut group, amount_of_blocks, "opt_spread");
    }
    group.finish()
}

fn benchmark_optimization_with_amount_of_blocks<OptimizationChip: Blake2bInstructions<Fr>>(
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    optimization_name: &str)
{
    group.bench_function(
        BenchmarkId::new(optimization_name, amount_of_blocks),
        |b| b.iter_batched(
            || {
                let ci = random_input_for_desired_blocks(amount_of_blocks);
                let circuit = CircuitRunner::create_circuit_for_inputs_optimization::<OptimizationChip>(ci.clone());
                (circuit, ci.4)
            },
            |(circuit, expected)| CircuitRunner::mock_prove_with_public_inputs_ref(&expected, &circuit),
            BatchSize::SmallInput
        ),
    );
}

fn random_input_for_desired_blocks(
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
