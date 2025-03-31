use blake2b_halo2::examples::circuit_runner::CircuitRunner;
use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput};
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::poly::kzg::params::ParamsKZG;

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

        benchmark_proof(
            &params,
            &mut group,
            amount_of_blocks,
            "opt_recycle",
        );
    }
    group.finish()
}

fn benchmark_proof(
    params: &ParamsKZG<Bn256>,
    group: &mut BenchmarkGroup<WallTime>,
    amount_of_blocks: usize,
    name: &str,
) {
    let ci = random_input_for_desired_blocks(amount_of_blocks);
    let expected_output_fields = ci.4.clone();

    let circuit = CircuitRunner::create_circuit_for_inputs_optimization(ci);
    let vk = CircuitRunner::create_vk(&circuit, params);
    let pk = CircuitRunner::create_pk(&circuit, vk.clone());

    group.bench_function(BenchmarkId::new(name, amount_of_blocks), |b| {
        b.iter(|| {
            CircuitRunner::create_proof(&expected_output_fields, circuit.clone(), &params, &pk)
        })
    });
}
