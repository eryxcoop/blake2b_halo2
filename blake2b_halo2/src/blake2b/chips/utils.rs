use ff::PrimeField;
use num_bigint::BigUint;

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