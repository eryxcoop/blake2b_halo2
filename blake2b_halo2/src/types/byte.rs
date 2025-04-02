use ff::PrimeField;
use halo2_proofs::utils::rational::Rational;
use num_bigint::BigUint;
use crate::types::get_word_biguint_from_le_field;

/// The inner type of AssignedByte. A wrapper around `u8`
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

impl Byte {
    /// Creates a new [Byte] element. When the byte is created, it is constrained to be in the
    /// range [0, 255].
    pub fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from(255u8));
        Byte(bi_v.to_bytes_le().first().copied().unwrap())
    }
}

/// Allows us to call the .assign_advice() method of the region with a Byte as its value
impl<F: PrimeField> From<&Byte> for Rational<F> {
    fn from(value: &Byte) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}