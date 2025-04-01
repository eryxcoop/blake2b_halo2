/// All these types are created to enforce safety across our code. The main types are:
///
/// AssignedBit: It contains an AssignedCell that has a value in {true, false}.
///
/// AssignedByte: It contains an AssignedCell that has a value in [0, 255].
///
/// AssignedBlake2bWord: It contains an AssignedCell that has a value in [0, 2^64 - 1]
///
/// AssignedRow: It contains an AssignedBlake2bWord and 8 AssignedLimb, like
/// |Word|Limb|Limb|Limb|Limb|Limb|Limb|Limb|Limb| which is how it's going to be used in some cases
///
/// All these types are created with a range check in their creation, but also they're created in
/// a context where its value has been constrained by a restriction to be in range.
///
/// Everytime you see an AssignedByte, AssignedBlake2bWord or AssignedRow, you can be certain
/// that all their values were range checked (both in the synthesize and in the circuit constraints)

use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Cell, Region, Value};
use num_bigint::BigUint;
use std::fmt::Debug;
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::utils::rational::Rational;


/// Native type for an [AssignedCell] that hasn't been constrained yet
pub(crate) type AssignedNative<F> = AssignedCell<F, F>;

/// The inner type of AssignedByte. A wrapper around `u8`
#[derive(Copy, Clone, Debug)]
struct Byte(pub u8);

impl Byte {
    /// Creates a new [Byte] element. When the byte is created, it is constrained to be in the
    /// range [0, 255].
    fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from(255u8));
        Byte(bi_v.to_bytes_le().first().copied().unwrap())
    }
}
/// The inner type of AssignedBlake2bWord. A wrapper around `u64`
#[derive(Copy, Clone, Debug)]
pub(crate) struct Blake2bWord(pub u64);

impl From<u64> for Blake2bWord {
    /// An u64 has a trivial conversion into a [Blake2bWord]
    fn from(value: u64) -> Self { Blake2bWord(value) }
}

/// This allows us to call the .assign_advice() method of the region with an AssignedBlake2bWord
/// as its value
impl<F: PrimeField> From<&Blake2bWord> for Rational<F> {
    fn from(value: &Blake2bWord) -> Self {
        Self::Trivial(F::from(value.0))
    }
}

impl<F: PrimeField> From<&Byte> for Rational<F> {
    fn from(value: &Byte) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}

impl<F: PrimeField> From<&Bit> for Rational<F> {
    fn from(value: &Bit) -> Self {
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

    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }
}

/// The inner type of AssignedBit. A wrapper around `bool`
#[derive(Copy, Clone, Debug)]
pub(crate) struct Bit(pub bool);

impl Bit {
    fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v == BigUint::from(0u8) || bi_v == BigUint::from(1u8));
        let bit = bi_v.to_bytes_le().first().copied().unwrap();
        Bit(bit == 1)
    }
}

/// This wrapper type on `AssignedNative<F>` is designed to enforce type safety
/// on assigned bits. It is used in the addition chip to enforce that the
/// carry value is 0 or 1
#[derive(Clone, Debug)]
#[must_use]
pub(crate) struct AssignedBit<F: PrimeField>(pub AssignedCell<Bit, F>);

impl<F: PrimeField> AssignedBit<F> {
    pub(crate) fn assign_advice_bit(
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
}

#[derive(Clone, Debug)]
#[must_use]
pub(crate) struct AssignedBlake2bWord<F: PrimeField>(pub AssignedCell<Blake2bWord, F>);

impl<F: PrimeField> AssignedBlake2bWord<F> {
    pub(crate) fn assign_advice_word(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        value: Value<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let word_value = value.map(|v| {
            let bi_v = get_word_biguint_from_le_field(v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from((1u128 << 64) - 1));
            let mut bytes = bi_v.to_bytes_le();
            bytes.resize(8, 0);
            // let first_8_bytes: [u8; 8] = bytes[..8].try_into().unwrap();
            Blake2bWord(u64::from_le_bytes(bytes.try_into().unwrap()))
        });
        // Create AssignedCell with the same value but different type
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || word_value)?);
        Ok(assigned_byte)
    }

    pub(crate) fn assign_fixed_word(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        word_value: Blake2bWord,
    ) -> Result<Self, Error> {
        let result =
            region.assign_advice_from_constant(|| annotation, column, offset, word_value)?;
        Ok(Self(result))
    }

    pub(crate) fn value(&self) -> Value<Blake2bWord> {
        self.0.value().cloned()
    }

    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }
}

/// Given a field element and a limb index in little endian form, this function checks that the
/// field element is in range [0, 2^64-1]. If it's not, it will fail.
/// We assume that the internal representation of the field is in little endian form. If it's
/// not, the result is undefined and probably incorrect.
/// Finally, it returns a [BigUint] holding the field element value.
pub(crate) fn get_word_biguint_from_le_field<F: PrimeField>(fe: F) -> BigUint {
    let field_internal_representation = fe.to_repr(); // Should be in little-endian
    let (bytes, zeros) = field_internal_representation.as_ref().split_at(8);

    let field_is_out_of_range = zeros.iter().any(|&el| el != 0u8);

    if field_is_out_of_range {
        panic!("Arguments to the function are incorrect")
    } else {
        BigUint::from_bytes_le(bytes)
    }
}

/// We use this type to model the Row we generally use along this circuit. This row has the
/// following shape:
/// full_number | limb_0 | limb_1 | limb_2 | limb_3 | limb_4 | limb_5 | limb_6 | limb_7
///
/// Where full_number is a Blake2bWord (64 bits) and the limbs constitute the little endian repr
///of the full_number (each limb is an AssignedByte)
#[derive(Debug)]
pub(crate) struct AssignedRow<F: PrimeField> {
    pub full_number: AssignedBlake2bWord<F>,
    pub limbs: [AssignedByte<F>; 8],
}

impl<F: PrimeField> AssignedRow<F> {
    pub(crate) fn new(full_number: AssignedBlake2bWord<F>, limbs: [AssignedByte<F>; 8]) -> Self {
        Self { full_number, limbs }
    }
}
