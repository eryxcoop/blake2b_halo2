use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use halo2_proofs::poly::kzg::params::ParamsKZG;
use halo2_proofs::halo2curves::bn256::{Bn256};
use blake2b_halo2::blake2b::chips::opt_4_limbs::Blake2bChipOpt4Limbs;
use blake2b_halo2::blake2b::chips::opt_recycle::Blake2bChipOptRecycle;
use blake2b_halo2::blake2b::chips::opt_spread::Blake2bChipOptSpread;
use criterion::measurement::WallTime;
use blake2b_halo2::blake2b::chips::blake2b_generic::Blake2bInstructions;
use blake2b_halo2::blake2b::circuit_runner::CircuitRunner;

pub mod utils;
use utils::*;

criterion_group!(verify, benchmark_verification);
criterion_main!(verify);

pub fn benchmark_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    configure_group(&mut group);

    let params = ParamsKZG::<Bn256>::unsafe_setup(17, &mut rand::thread_rng());

    for amount_of_blocks in benchmarking_block_sizes() {
        group.throughput(Throughput::Bytes(amount_of_blocks as u64));

        benchmark_verification_iteration::<Blake2bChipOpt4Limbs>(
            &params,
            &mut group,
            amount_of_blocks,
            "opt_4_limbs",
        );
        benchmark_verification_iteration::<Blake2bChipOptRecycle>(
            &params,
            &mut group,
            amount_of_blocks,
            "opt_recycle",
        );
        benchmark_verification_iteration::<Blake2bChipOptSpread>(
            &params,
            &mut group,
            amount_of_blocks,
            "opt_spread",
        );
    }
    group.finish()
}

fn benchmark_verification_iteration<OptimizationChip: Blake2bInstructions>(
    params: &ParamsKZG<Bn256>,
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    name: &str,
) {
    let ci = random_input_for_desired_blocks(amount_of_blocks);
    let expected_output_fields = ci.4.clone();

    let circuit = CircuitRunner::create_circuit_for_inputs_optimization::<OptimizationChip>(ci);
    let vk = CircuitRunner::create_vk(&circuit, params);
    let pk = CircuitRunner::create_pk(&circuit, vk.clone());
    let proof = CircuitRunner::create_proof(&expected_output_fields, circuit.clone(), &params, &pk);

    group.bench_function(BenchmarkId::new(name, amount_of_blocks), |b| {
        b.iter(|| CircuitRunner::verify(&expected_output_fields, &params, pk.clone(), &proof))
    });
}
