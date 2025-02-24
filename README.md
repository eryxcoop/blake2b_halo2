# blake2b_halo2
This repo holds an optimized Blake2b implementation in Halo2 prover.

* We are using [this halo2 version](https://github.com/input-output-hk/halo2) to build our circuits.
* The cargo version should be 1.84.0 or higher (no need for nightly).

The repo is divided into three parts:
* Under the directory ```rust_implementation``` there's an implementation in plain Rust of the algorithm Blake2b with its test vector. This implementation is based on the C implementation in the [Blake2 RFC](https://datatracker.ietf.org/doc/html/rfc7693.html).
* Under the directory ```blake2b_halo2``` there are all the things that have to do with Halo2. In particular, there are Halo2 chips that implement primitives for operating modulo $2^{64}$, a chip for the Blake2b operation and tests for all of the above.
* Under the directory ```interface``` there is a simple package that lets you try the implementation. More details below.   


# Different blake implementations

We use features to toggle between different implementations. Right now we have three implementations (for more information about them you can see our [Blake2b implementation in Halo2](https://hackmd.io/@BjOWve_hTxGZidE1ii0HJg/HkVu20JFkx) documentation).

To use our A implementation, set the `sum_with_4_limbs` and `xor_with_table` features. 
To use our B implementation, set the `sum_with_8_limbs` and `xor_with_table` features.
To use our C implementation, set the `sum_with_8_limbs` and `xor_with_spread` features.

If you don't set any feature, the defaults will be `sum_with_4_limbs` and `xor_with_table`. 

# Trying the implementation
Under the directory ```interface``` you can try the halo2 implementation of Blake2b.
Just fill the ```src/inputs.json``` file with the message, key and desired output length (in bytes) and run the following commands:

To try the optimization A: 

```cargo run --release --features blake2b_halo2/sum_with_4_limbs,blake2b_halo2/xor_with_table```

To try the optimization B:

```cargo run --release --features blake2b_halo2/sum_with_8_limbs,blake2b_halo2/xor_with_table```

To try the optimization C:

```cargo run --release --features blake2b_halo2/sum_with_8_limbs,blake2b_halo2/xor_with_spread```


# Running the tests

We have unit tests for all our auxiliar chips and the vector tests for the Blake2b implementation. All the tests should be executed on the ```blake2b_halo2``` directory.

To test the optimization A:

```cargo test --release --features sum_with_4_limbs,xor_with_table test_hashes_in_circuit_```

To test the optimization B:

```cargo test --release --features sum_with_8_limbs,xor_with_table test_hashes_in_circuit_```

To test the optimization C:

```cargo test --release --features sum_with_8_limbs,xor_with_spread test_hashes_in_circuit_```


Those tests use the same test vector than the plain Rust implementation. Running the above tests can take some time since there are 512 tests in the test vector, and each one repeats all the static procedures (like creating big lookup tables), but it shouldn't take more than 2 minutes in release mode.

To test the auxiliar chips:

```cargo test --release -- --skip test_hashes_in_circuit_```
