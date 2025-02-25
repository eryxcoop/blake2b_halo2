use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::halo2curves::bn256::Fr;
use blake2b_halo2::circuit_runner::CircuitRunner;

fn criterion_benchmark(c: &mut Criterion) {

    let input = vec![];
    let input_size = 0;
    let output_size = 1;
    let key_size = 0;
    let key = vec![];
    let expected_output_state = vec![Fr::from(120)];
    let circuit = CircuitRunner::create_circuit_for_inputs(input, input_size, key, key_size, output_size);

    let func = || CircuitRunner::mock_prove_with_public_inputs_ref(&expected_output_state, &circuit);

    c.bench_function("fib 20", |b| b.iter(func));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);