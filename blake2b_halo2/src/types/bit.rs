use crate::types::*;
use ff::PrimeField;
use halo2_proofs::utils::rational::Rational;

/// The inner type of AssignedBit. A wrapper around `bool`
#[derive(Copy, Clone, Debug)]
pub(crate) struct Bit(pub bool);

impl Bit {
    /// Creates a new [Bit] element. When the byte is created, it is constrained to be in the
    /// range [0, 1] and its internal member is a boolean.
    fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v == BigUint::from(0u8) || bi_v == BigUint::from(1u8));
        let bit = bi_v.to_bytes_le().first().copied().unwrap();
        Bit(bit == 1)
    }
}

/// Allows us to call the .assign_advice() method of the region with a Bit as its value
impl<F: PrimeField> From<&Bit> for Rational<F> {
    fn from(value: &Bit) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}
