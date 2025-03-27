use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Cell, Region, Value};
use num_bigint::BigUint;
use std::fmt::Debug;
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::utils::rational::Rational;

/// All these types are created to enforce safety across our code. The three main types are:
///
/// AssignedByte: It contains an AssignedCell that has a value between 0 and 255.
///
/// AssignedBlake2bWord: It contains an AssignedCell that has a value between 0 and 2^64 - 1
///
/// AssignedRow: It contains an AssignedBlake2bWord and 8 AssignedLimb
///
/// All these types are created at the same place where a range check is enabled in their values
/// So everytime you see an AssignedByte, AssignedBlake2bWord or AssignedRow, you can be certain
/// that all their values were range checked

pub type AssignedNative<F> = AssignedCell<F, F>;

/// The inner type of AssignedByte. A wrapper around `u8`
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

/// The inner type of AssignedBlake2bWord. A wrapper around `u64`
#[derive(Copy, Clone, Debug)]
pub struct Blake2bWord(pub u64);

impl From<u128> for Blake2bWord {
    fn from(value: u128) -> Self {
        Blake2bWord(value as u64)
    }
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

/// This wrapper type on `AssignedCell<Byte, F>` is designed to enforce type safety
/// on assigned bytes. It prevents the user from creating an `AssignedByte`
/// without using the designated entry points, which guarantee (with
/// constraints) that the assigned value is indeed in the range [0, 256).
#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedByte<F: PrimeField>(AssignedCell<Byte, F>);

impl<F: PrimeField> AssignedByte<F> {
    pub fn copy_advice_byte(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        cell_to_copy: AssignedNative<F>
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = cell_to_copy.value().map(|v| {
            let bi_v = fe_to_big(*v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from(255u8));
            Byte(bi_v.to_bytes_le().first().copied().unwrap())
        });
        // Create AssignedCell with the same value but different type
        let assigned_byte = Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        // Constrain cells have equal values
        region.constrain_equal(cell_to_copy.cell(), assigned_byte.cell())?;

        Ok(assigned_byte)
    }

    pub fn assign_advice_byte(
        region: &mut Region<F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        value: Value<F>
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = value.map(|v| {
            let bi_v = fe_to_big(v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from(255u8));
            Byte(bi_v.to_bytes_le().first().copied().unwrap())
        });
        // Create AssignedCell with the same value but different type
        let assigned_byte = Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        Ok(assigned_byte)
    }

    pub fn cell(&self) -> Cell {
        self.0.cell()
    }

    pub fn inner_value(&self) -> AssignedCell<Byte,F> {
        self.0.clone()
    }
}



/// This wrapper type on `AssignedNative<F>` is designed to enforce type safety
/// on assigned bits. It is used in the addition chip to enforce that the
/// carry value is 0 or 1
#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedBit<F: PrimeField>(pub AssignedNative<F>);

impl<F: PrimeField> AssignedBit<F> {
    pub fn new(value: AssignedNative<F>) -> Self {
        Self { 0: value }
    }

    pub fn value(&self) -> Value<F> {
        self.0.value().map(|v| {
            let bi_v = fe_to_big(*v);
            #[cfg(not(test))]
            assert!(bi_v == BigUint::from(1u8) || bi_v == BigUint::from(0u8));
            if bi_v == BigUint::from(1u8) {
                F::from(1)
            } else {
                F::from(0)
            }
        })
    }

    pub fn cell(&self) -> Cell {
        self.0.cell()
    }

    pub fn inner_value(&self) -> AssignedNative<F> {
        self.0.clone()
    }
}

#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedBlake2bWord<F: PrimeField>(pub AssignedNative<F>);

impl<F: PrimeField> AssignedBlake2bWord<F> {
    pub fn new(value: AssignedNative<F>) -> Self {
        Self { 0: value }
    }

    pub fn value(&self) -> Value<Blake2bWord> {
        self.0.value().map(|v| {
            let bi_v = fe_to_big(*v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from((1u128 << 64) - 1));
            let mut bytes = bi_v.to_bytes_le();
            bytes.resize(8, 0);
            let first_8_bytes: [u8; 8] = bytes[..8].try_into().unwrap();
            Blake2bWord(u64::from_le_bytes(first_8_bytes))
        })
    }

    pub fn cell(&self) -> Cell {
        self.0.cell()
    }

    pub fn inner_value(&self) -> AssignedNative<F> {
        self.0.clone()
    }
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

impl<F: PrimeField> From<AssignedBlake2bWord<F>> for AssignedNative<F> {
    fn from(value: AssignedBlake2bWord<F>) -> Self {
        value.0
    }
}

impl<F: PrimeField> From<AssignedNative<F>> for AssignedBlake2bWord<F> {
    fn from(value: AssignedNative<F>) -> Self {
        AssignedBlake2bWord::new(value)
    }
}

/// We use this type to model the Row we generally use along this circuit. This row has the
/// following shape:
/// full_number | limb_0 | limb_1 | limb_2 | limb_3 | limb_4 | limb_5 | limb_6 | limb_7 | limb_8
///
/// Where full_number is a Blake2bWord (64 bits) and the limbs constitute the little endian repr
///of the full_number (each limb is an AssignedByte)
#[derive(Debug)]
pub struct AssignedRow<F: PrimeField> {
    pub full_number: AssignedBlake2bWord<F>,
    pub limbs: [AssignedByte<F>; 8],
}

impl<F: PrimeField> AssignedRow<F> {
    pub fn new(full_number: AssignedBlake2bWord<F>, limbs: [AssignedByte<F>; 8]) -> Self {
        Self { full_number, limbs }
    }
}

