use blake2b_halo2::usage_utils::circuit_runner::CircuitRunner;
use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::poly::kzg::params::ParamsKZG;

pub mod utils;
use utils::*;

criterion_group!(pk, benchmark_proving_key_generation);
criterion_main!(pk);

pub fn benchmark_proving_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving_key");
    configure_group(&mut group);

    let params = ParamsKZG::<Bn256>::unsafe_setup(17, &mut rand::thread_rng());

    for amount_of_blocks in benchmarking_block_sizes() {
        group.throughput(Throughput::Bytes(amount_of_blocks as u64));

        benchmark_proving_key(&params, &mut group, amount_of_blocks, "opt_recycle");
    }
    group.finish()
}

fn benchmark_proving_key(
    params: &ParamsKZG<Bn256>,
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    name: &str,
) {
    let ci = random_input_for_desired_blocks(amount_of_blocks);
    let circuit = CircuitRunner::create_circuit_for_packed_inputs(ci);
    let vk = CircuitRunner::create_vk(&circuit, params);

    group.bench_function(BenchmarkId::new(name, amount_of_blocks), |b| {
        b.iter(|| CircuitRunner::create_pk(&circuit, vk.clone()))
    });
}
