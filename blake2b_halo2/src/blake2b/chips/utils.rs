use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Region, Value};
use num_bigint::BigUint;
use halo2_proofs::plonk::Error;

/// Enforces the field's modulus to be greater than 2^65, which is a necessary condition for the rot63 gate to be sound.
pub fn enforce_modulus_size<F: PrimeField>() {
    let modulus_bytes: Vec<u8> = hex::decode(F::MODULUS.trim_start_matches("0x"))
        .expect("Modulus is not a valid hex number");
    let modulus = BigUint::from_bytes_be(&modulus_bytes);
    let two_pow_65 = BigUint::from(1u128 << 65);
    assert!(modulus > two_pow_65, "Field modulus must be greater than 2^65");
}

/// Enforces the output and key sizes.
/// Output size must be between 1 and 64 bytes.
/// Key size must be between 0 and 64 bytes.
pub fn enforce_input_sizes(output_size: usize, key_size: usize) {
    assert!(output_size <= 64, "Output size must be between 1 and 64 bytes");
    assert!(output_size > 0, "Output size must be between 1 and 64 bytes");
    assert!(key_size <= 64, "Key size must be between 1 and 64 bytes");
}

/// Sets copy constraints to the part of the state that is copied from iv_constants.
pub fn constrain_initial_state<F: PrimeField>(
    region: &mut Region<F>,
    global_state: &[AssignedCell<F, F>; 8],
    iv_constants: &[AssignedCell<F, F>; 8],
) -> Result<(), Error> {
    for i in 0..8 {
        region.constrain_equal(iv_constants[i].cell(), global_state[i].cell())?;
    }
    Ok(())
}

/// Extracts the full number cell of each of the state rows
pub fn get_full_number_of_each<F: PrimeField>(
    current_block_rows: [Vec<AssignedCell<F, F>>; 16],
) -> [AssignedCell<F, F>; 16] {
    current_block_rows.iter().map(|row| row[0].clone()).collect::<Vec<_>>().try_into().unwrap()
}

/// The 'processed_bytes_count' is a variable in the algorithm that changes with every iteration,
/// in each iteration we compute the new value for it.
pub fn compute_processed_bytes_count_value_for_iteration<F: PrimeField>(
    iteration: usize,
    is_last_block: bool,
    input_size: usize,
    empty_key: bool,
) -> Value<F> {
    let processed_bytes_count = if is_last_block {
        input_size + if empty_key { 0 } else { 128 }
    } else {
        128 * (iteration + 1)
    };

    Value::known(F::from(processed_bytes_count as u64))
}

/// Computes the edge cases in the amount of blocks to process.
pub fn get_total_blocks_count(
    input_blocks: usize,
    is_input_empty: bool,
    is_key_empty: bool,
) -> usize {
    if is_key_empty {
        if is_input_empty {
            // If there's no input and no key, we still need to process one block of zeroes.
            1
        } else {
            input_blocks
        }
    } else if is_input_empty {
        // If there's no input but there's key, key is processed in the first and only block.
        1
    } else {
        // Key needs to be processed in a block alone, then come the input blocks.
        input_blocks + 1
    }
}