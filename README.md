# blake2b_halo2
This repo holds an optimized Blake2b implementation in Halo2 prover.

* We are using [this halo2 version](https://github.com/input-output-hk/halo2) to build our circuits.
* The cargo version should be 1.84.0 or higher (no need for nightly).

The repo is divided into three parts:
* Under the directory ```rust_implementation``` there's an implementation in plain Rust of the algorithm Blake2b with its test vector. This implementation is based on the C implementation in the [Blake2 RFC](https://datatracker.ietf.org/doc/html/rfc7693.html).
* Under the directory ```blake2b_halo2``` there are all the things that have to do with Halo2. In particular, there are Halo2 chips that implement primitives for operating modulo 2⁶⁴, a chip for the Blake2b operation and tests for all of the above.
* Under the directory ```interface``` there is a simple package that lets you try the implementation. More details below.

# Different blake implementations

## Documentation

We have a [documentation](https://hackmd.io/@BjOWve_hTxGZidE1ii0HJg/HkVu20JFkx) where you can find more detail about 
every implementation and the optimizations we made. Also you can find more explanation of all our gates.

## Implementations

We use features to toggle between different implementations. Right now we have three implementations (for more information about them you can see our documentation).

To use our 'opt_4_limbs' implementation, set the `opt_4_limbs` feature.

To use our 'opt_recycle' implementation, set the `opt_recycle` feature.

To use our 'opt_spread' implementation, set the `opt_spread` feature.


To give a quick summary:

opt_4_limbs ----> turns on the sum operation with 4 limbs instead of 8 and xor with a precomputed table.

opt_recycle ----> turns on the sum operation with 8 limbs and xor with a precomputed table.

opt_spread  ----> turns on the sum operation with 8 limbs and xor with an 8-bit spread table.

# Trying the implementation
Under the directory ```interface``` you can try the halo2 implementation of Blake2b.
Just fill the ```src/inputs.json``` file with the message, key and desired output length (in bytes) and run the following commands:

To try the optimization 'opt_4_limbs': 

```cargo run --release --features interface/opt_4_limbs```

To try the optimization 'opt_recycle':

```cargo run --release --features interface/opt_recycle```

To try the optimization 'opt_spread':

```cargo run --release --features interface/opt_spread```


# Running the tests

We have unit tests for all our auxiliar chips and the vector tests for the Blake2b implementation. All the tests should be executed on the ```blake2b_halo2``` directory.

To test the optimization 'opt_4_limbs':

```cargo test --release --features blake2b_halo2/opt_4_limbs test_hashes_in_circuit_```

To test the optimization 'opt_recycle':

```cargo test --release --features blake2b_halo2/opt_recycle test_hashes_in_circuit_```

To test the optimization 'opt_spread':

```cargo test --release --features blake2b_halo2/opt_spread test_hashes_in_circuit_```


Those tests use the same test vector than the plain Rust implementation. Running the above tests can take some time since there are 512 tests in the test vector, and each one repeats all the static procedures (like creating big lookup tables), but it shouldn't take more than 2 minutes in release mode.

To test the auxiliar chips:

```cargo test --release --features blake2b_halo2/opt_recycle -- --skip test_hashes_in_circuit_```

# Benchmarking
Just run

```cargo bench```

The report should be found in ```/target/criterion/report/index.html```. 

Alternatively, you can find our own generated report in ```/blake2b_halo2/benches/report/index.html```. 

There are 5 targets for benchmarking: mocked proving, verification key generation, proving key generation, proof generation and verification. Each one will compare all the optimizations over inputs of different size. Running all the benchmarks can take quite some time, so if you want to run one specific target use:

```cargo bench --bench <TARGET_NAME>```

where <TARGET_NAME> is one of the following:
* mocked_proving
* vk_generation
* pk_generation
* proof_generation
* verification