use std::ops::BitXor;
use ff::PrimeField;
use halo2_proofs::circuit::{Cell, Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::utils::rational::Rational;
use crate::base_operations::types::*;
use num_bigint::BigUint;

/// The inner type of AssignedByte. A wrapper around `u8`
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

impl Byte {
    /// Creates a new [Byte] element. When the byte is created, it is constrained to be in the
    /// range [0, 255].
    pub fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from(255u8)); //[zhiyong]: no need to check in CPU, since it will be constrained in the circuit anyway
        Byte(bi_v.to_bytes_le().first().copied().unwrap())
    }
}

impl BitXor for Byte {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Allows us to call the .assign_advice() method of the region with a Byte as its value
impl<F: PrimeField> From<&Byte> for Rational<F> {
    fn from(value: &Byte) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}

/// This wrapper type on `AssignedCell<Byte, F>` is designed to enforce type safety
/// on assigned bytes. It prevents the user from creating an `AssignedByte`
/// without using the designated entry points, which guarantee (with
/// constraints) that the assigned value is indeed in the range [0, 256).
#[derive(Clone, Debug)]
pub(crate) struct AssignedByte<F: PrimeField>(AssignedCell<Byte, F>);

impl<F: PrimeField> AssignedByte<F> {
    pub(in crate::base_operations) fn copy_advice_byte_from_native(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        cell_to_copy: AssignedNative<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = cell_to_copy.value().map(|v| Byte::new_from_field(*v));
        // Create AssignedCell with the same value but different type
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        // Constrain cells have equal values
        region.constrain_equal(cell_to_copy.cell(), assigned_byte.cell())?;

        Ok(assigned_byte)
    }

    pub(in crate::base_operations) fn copy_advice_byte(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        cell_to_copy: AssignedByte<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = cell_to_copy.0.value().map(|v| Byte(v.0));
        // Create AssignedCell with the same value but different type
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        // Constrain cells have equal values
        region.constrain_equal(cell_to_copy.cell(), assigned_byte.cell())?;

        Ok(assigned_byte)
    }

    pub(in crate::base_operations) fn assign_advice_byte(region: &mut Region<F>, annotation: &str, column: Column<Advice>, offset: usize, byte_value: Value<Byte>) -> Result<AssignedByte<F>, Error> {
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        Ok(assigned_byte)
    }

    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }

    pub(crate) fn value(&self) -> Value<Byte> {
        self.0.value().cloned()
    }
}
