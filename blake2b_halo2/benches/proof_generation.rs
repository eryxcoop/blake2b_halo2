use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use halo2_proofs::poly::kzg::params::ParamsKZG;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use blake2b_halo2::blake2b::chips::opt_4_limbs::Blake2bChipOpt4Limbs;
use blake2b_halo2::blake2b::chips::opt_recycle::Blake2bChipOptRecycle;
use blake2b_halo2::blake2b::chips::opt_spread::Blake2bChipOptSpread;
use blake2b_halo2::blake2b::instructions::Blake2bInstructions;
use criterion::measurement::WallTime;
use blake2b_halo2::circuit_runner::CircuitRunner;

pub mod utils;
use utils::*;

criterion_group!(proof, benchmark_proof_generation);
criterion_main!(proof);

pub fn benchmark_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof");
    configure_group(&mut group);

    let params = ParamsKZG::<Bn256>::unsafe_setup(17, &mut rand::thread_rng());

    for amount_of_blocks in benchmarking_block_sizes() {
        group.throughput(Throughput::Bytes(amount_of_blocks as u64));

        benchmark_proof::<Blake2bChipOpt4Limbs<Fr>>(&params, &mut group, amount_of_blocks, "opt_4_limbs");
        benchmark_proof::<Blake2bChipOptRecycle<Fr>>(&params, &mut group, amount_of_blocks, "opt_recycle");
        benchmark_proof::<Blake2bChipOptSpread<Fr>>(&params, &mut group, amount_of_blocks, "opt_spread");
    }
    group.finish()
}

fn benchmark_proof<OptimizationChip: Blake2bInstructions<Fr>>(
    params: &ParamsKZG<Bn256>,
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    name: &str)
{
    let ci = random_input_for_desired_blocks(amount_of_blocks);
    let expected_output_fields = ci.4.clone();

    let circuit = CircuitRunner::create_circuit_for_inputs_optimization::<OptimizationChip>(ci);
    let vk = CircuitRunner::create_vk(&circuit, params);
    let pk = CircuitRunner::create_pk(&circuit, vk.clone());

    group.bench_function(BenchmarkId::new(name, amount_of_blocks), |b| {
        b.iter(|| CircuitRunner::create_proof(&expected_output_fields, circuit.clone(), &params, &pk))
    });
}