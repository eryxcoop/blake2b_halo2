use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Cell, Region, Value};
use std::ops::{BitXor, Sub};
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::utils::rational::Rational;
use crate::types::*;
use num_bigint::BigUint;
use crate::base_operations::decompose_8::AssignedBlake2bWord;

/// The inner type of AssignedBlake2bWord. A wrapper around `u64`
#[derive(Copy, Clone, Debug)]
pub(crate) struct Blake2bWord(pub u64);

impl Blake2bWord {
    /// Creates a new [Blake2bWord] element. When the Blake2bWord is created, it is constrained to be in the
    /// range [0, 2^64 - 1].
    fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from((1u128 << 64) - 1));
        let mut bytes = bi_v.to_bytes_le();
        bytes.resize(8, 0);
        u64::from_le_bytes(bytes.try_into().unwrap()).into()
    }

    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }}

impl BitXor for Blake2bWord {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for Blake2bWord {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl From<u64> for Blake2bWord {
    /// An u64 has a trivial conversion into a [Blake2bWord]
    fn from(value: u64) -> Self { Blake2bWord(value) }
}

impl<F: PrimeField> From<AssignedCell<Blake2bWord, F>> for AssignedBlake2bWord<F> {
    fn from(value: AssignedCell<Blake2bWord, F>) -> Self {
        Self(value)
    }
}

/// Allows us to call the .assign_advice() method of the region with an Blake2bWord as its value
impl<F: PrimeField> From<&Blake2bWord> for Rational<F> {
    fn from(value: &Blake2bWord) -> Self {
        Self::Trivial(F::from(value.0))
    }
}