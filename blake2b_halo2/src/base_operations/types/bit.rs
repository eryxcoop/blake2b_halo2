use crate::base_operations::types::*;
use ff::PrimeField;
use halo2_proofs::circuit::{Cell, Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::utils::rational::Rational;

/// The inner type of AssignedBit. A wrapper around `bool`
#[derive(Copy, Clone, Debug)]
pub(crate) struct Bit(bool);

impl Bit {
    /// Creates a new [Bit] element. When the byte is created, it is constrained to be in the
    /// range [0, 1] and its internal member is a boolean.
    pub(crate) fn new_from_field<F: PrimeField>(field: F) -> Self {
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

/// This wrapper type on `AssignedNative<F>` is designed to enforce type safety
/// on assigned bits. It is used in the addition chip to enforce that the
/// carry value is 0 or 1
#[derive(Clone, Debug)]
#[must_use]
pub(crate) struct AssignedBit<F: PrimeField>(AssignedCell<Bit, F>);

impl<F: PrimeField> AssignedBit<F> {
    pub(in crate::base_operations) fn assign_advice_bit(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        value: Value<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let bit_value = value.map(|v| Bit::new_from_field(v));
        // Create AssignedCell with the same value but different type
        let assigned_bit =
            Self(region.assign_advice(|| annotation, column, offset, || bit_value)?);
        Ok(assigned_bit)
    }

    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }
}