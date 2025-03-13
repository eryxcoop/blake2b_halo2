use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use halo2_proofs::poly::kzg::params::ParamsKZG;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use blake2b_halo2::blake2b::chips::opt_4_limbs::Blake2bChipOpt4Limbs;
use blake2b_halo2::blake2b::chips::opt_recycle::Blake2bChipOptRecycle;
use blake2b_halo2::blake2b::chips::opt_spread::Blake2bChipOptSpread;
use blake2b_halo2::blake2b::instructions::Blake2bInstructions;
use criterion::measurement::WallTime;
use blake2b_halo2::blake2b::circuit_runner::CircuitRunner;

pub mod utils;
use utils::*;

criterion_group!(vk, benchmark_verification_key_generation);
criterion_main!(vk);

pub fn benchmark_verification_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_key");
    configure_group(&mut group);

    let params = ParamsKZG::<Bn256>::unsafe_setup(17, &mut rand::thread_rng());

    for amount_of_blocks in benchmarking_block_sizes() {
        group.throughput(Throughput::Bytes(amount_of_blocks as u64));

        benchmark_verification_key::<Blake2bChipOpt4Limbs<Fr>>(&params, &mut group, amount_of_blocks, "opt_4_limbs");
        benchmark_verification_key::<Blake2bChipOptRecycle<Fr>>(&params, &mut group, amount_of_blocks, "opt_recycle");
        benchmark_verification_key::<Blake2bChipOptSpread<Fr>>(&params, &mut group, amount_of_blocks, "opt_spread");
    }
    group.finish()
}

fn benchmark_verification_key<OptimizationChip: Blake2bInstructions>(
    params: &ParamsKZG<Bn256>,
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    name: &str)
{
    group.bench_function(BenchmarkId::new(name, amount_of_blocks), |b| {
        b.iter_batched(
            || {
                let ci = random_input_for_desired_blocks(amount_of_blocks);
                let circuit = CircuitRunner::create_circuit_for_inputs_optimization::<
                    OptimizationChip,
                >(ci.clone());
                circuit
            },
            |circuit| {
                CircuitRunner::create_vk(&circuit, params)
            },
            BatchSize::SmallInput,
        )
    });
}