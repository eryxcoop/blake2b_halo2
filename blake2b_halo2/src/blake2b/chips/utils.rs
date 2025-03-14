use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Region, Value};
use num_bigint::BigUint;
use halo2_proofs::plonk::Error;
use crate::auxiliar_functions::value_for;

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
    iv_constant_cells: &[AssignedCell<F, F>; 8],
) -> Result<(), Error> {
    for i in 0..8 {
        region.constrain_equal(iv_constant_cells[i].cell(), global_state[i].cell())?;
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

    value_for(processed_bytes_count as u64)
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

/// This method constrains the padding cells to equal zero. The amount of constraints
/// depends on the input size and the key size, which makes sense since those values are known
/// at circuit building time.
/// The idea is that since we decompose the state into 8 limbs, we already have the input
/// bytes in the trace. It's just a matter of iterating the cells in the correct order and knowing
/// which ones should equal zero. In Blake2b the padding is allways 0.
pub fn constrain_padding_cells_to_equal_zero<F: PrimeField>(
    region: &mut Region<F>,
    zeros_amount: usize,
    current_block_rows: &[Vec<AssignedCell<F, F>>; 16],
    zero_constant_cell: &AssignedCell<F, F>,
) -> Result<(), Error> {
    let mut constrained_padding_cells = 0;
    for row in (0..16).rev() {
        for limb in (1..9).rev() {
            if constrained_padding_cells < zeros_amount {
                region.constrain_equal(
                    current_block_rows[row][limb].cell(),
                    zero_constant_cell.cell(),
                )?;
                constrained_padding_cells += 1;
            }
        }
    }
    Ok(())
}

// ----- Blake2b constants -----

pub const BLAKE2B_BLOCK_SIZE: usize = 128;

pub const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

pub const ABCD: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

pub fn iv_constants<F: PrimeField>() -> [Value<F>; 8] {
    [
        value_for(0x6A09E667F3BCC908u128),
        value_for(0xBB67AE8584CAA73Bu128),
        value_for(0x3C6EF372FE94F82Bu128),
        value_for(0xA54FF53A5F1D36F1u128),
        value_for(0x510E527FADE682D1u128),
        value_for(0x9B05688C2B3E6C1Fu128),
        value_for(0x1F83D9ABFB41BD6Bu128),
        value_for(0x5BE0CD19137E2179u128),
    ]
}
