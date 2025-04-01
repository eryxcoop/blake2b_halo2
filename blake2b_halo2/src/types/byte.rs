use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Cell, Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::utils::rational::Rational;
use num_bigint::BigUint;
use crate::types;
use crate::types::AssignedNative;

/// The inner type of AssignedByte. A wrapper around `u8`
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

impl Byte {
    /// Creates a new [Byte] element. When the byte is created, it is constrained to be in the
    /// range [0, 255].
    fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = types::get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from(255u8));
        Byte(bi_v.to_bytes_le().first().copied().unwrap())
    }
}

/// This wrapper type on `AssignedCell<Byte, F>` is designed to enforce type safety
/// on assigned bytes. It prevents the user from creating an `AssignedByte`
/// without using the designated entry points, which guarantee (with
/// constraints) that the assigned value is indeed in the range [0, 256).
#[derive(Clone, Debug)]
pub(crate) struct AssignedByte<F: PrimeField>(AssignedCell<Byte, F>);

impl<F: PrimeField> AssignedByte<F> {
    /// Given an AssignedNative cell somewhere, this method copies it into trace[offset][column]
    /// while range-checking its value to be a Byte. This is one way we can obtain an [AssignedByte]
    /// from an [AssignedNative].
    pub(crate) fn copy_advice_byte_from_native(
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

    /// Given an AssignedByte cell somewhere, this method copies it into trace[offset][column]
    /// without range-checking its value to be a Byte, since it already comes from one.
    pub(crate) fn copy_advice_byte(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        cell_to_copy: AssignedByte<F>,
    ) -> Result<Self, Error> {
        Ok(Self(cell_to_copy.0.copy_advice(|| annotation, region, column, offset)?))
    }

    /// Given an arbitrary value, this method checks the value is in the range of a Byte (by
    /// creating a Byte object) and then assigns the byte into a cell.
    pub(crate) fn assign_advice_byte(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        value: Value<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = value.map(|v| Byte::new_from_field(v));
        // Create AssignedCell with the same value but different type
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        Ok(assigned_byte)
    }

    /// Getter for the internal cell
    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }
}

/// Allows us to call the .assign_advice() method of the region with a Byte as its value
impl<F: PrimeField> From<&Byte> for Rational<F> {
    fn from(value: &Byte) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}