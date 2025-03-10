use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use blake2b_halo2::blake2b::chips::opt_4_limbs::Blake2bChipOpt4Limbs;
use halo2_proofs::halo2curves::bn256::Fr;
use blake2b_halo2::blake2b::chips::opt_recycle::Blake2bChipOptRecycle;
use blake2b_halo2::blake2b::chips::opt_spread::Blake2bChipOptSpread;
use blake2b_halo2::blake2b::instructions::Blake2bInstructions;
use criterion::measurement::WallTime;
use blake2b_halo2::circuit_runner::CircuitRunner;

pub mod utils;
use utils::*;

criterion_group!(mocked_prover, benchmark_mocked_proving);
criterion_main!(mocked_prover);

pub fn benchmark_mocked_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("optimization_comparison");
    configure_group(&mut group);

    for amount_of_blocks in benchmarking_block_sizes() {
        group.throughput(Throughput::Bytes(amount_of_blocks as u64));

        benchmark_optimization_with_amount_of_blocks::<Blake2bChipOpt4Limbs<Fr>>(
            &mut group,
            amount_of_blocks,
            "opt_4_limbs",
        );
        benchmark_optimization_with_amount_of_blocks::<Blake2bChipOptRecycle<Fr>>(
            &mut group,
            amount_of_blocks,
            "opt_recycle",
        );
        benchmark_optimization_with_amount_of_blocks::<Blake2bChipOptSpread<Fr>>(
            &mut group,
            amount_of_blocks,
            "opt_spread",
        );
    }
    group.finish()
}

fn benchmark_optimization_with_amount_of_blocks<OptimizationChip: Blake2bInstructions<Fr>>(
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    optimization_name: &str,
) {
    group.bench_function(BenchmarkId::new(optimization_name, amount_of_blocks), |b| {
        b.iter_batched(
            || {
                let ci = random_input_for_desired_blocks(amount_of_blocks);
                let circuit = CircuitRunner::create_circuit_for_inputs_optimization::<
                    OptimizationChip,
                >(ci.clone());
                (circuit, ci.4)
            },
            |(circuit, expected)| {
                CircuitRunner::mock_prove_with_public_inputs_ref(&expected, &circuit)
            },
            BatchSize::SmallInput,
        )
    });
}