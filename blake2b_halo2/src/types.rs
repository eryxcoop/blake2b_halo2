use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Cell, Value};
use num_bigint::BigUint;
use std::fmt::Debug;


/// The inner type of AssignedByte.
// A wrapper around `u8` to have a type that we own and for which we can implement some necessary
// traits like `From<u64>`.
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

#[derive(Copy, Clone, Debug)]
pub struct Blake2bWord(pub u64);

impl From<u128> for Blake2bWord {
    fn from(value: u128) -> Self {
        Blake2bWord(value as u64)
    }
}

/*
impl<F: PrimeField> From<&Blake2bWord> for Rational<F> {
    fn from(value: &Blake2bWord) -> Self {
        Self::Trivial(F::from(value.0))
    }
}*/

pub type AssignedNative<F> = AssignedCell<F, F>;

/// Trait for accessing the value inside assigned circuit elements.
pub trait AssignedElement<F: PrimeField>: Clone + Debug {
    /// Represents the unassigned type corresponding to the [midnight_circuits::types::InnerValue]
    type Element: Clone + Debug;

    //constructor
    fn new(value: AssignedNative<F>) -> Self;

    /// Returns the value of the assigned element.
    fn value(&self) -> Value<Self::Element>;

    fn cell(&self) -> Cell;

    // TODO solo para pasos intermedios del refactor, despues se deberia sacar
    fn inner_value(&self) -> AssignedNative<F>;
}

/// This wrapper type on `AssignedNative<F>` is designed to enforce type safety
/// on assigned bytes. It prevents the user from creating an `AssignedByte`
/// without using the designated entry points, which guarantee (with
/// constraints) that the assigned value is indeed in the range [0, 256).
#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedByte<F: PrimeField>(AssignedNative<F>);

impl<F: PrimeField> AssignedElement<F> for AssignedByte<F> {
    type Element = Byte;

    fn new(value: AssignedNative<F>) -> Self {
        Self { 0: value }
    }

    fn value(&self) -> Value<Byte> {
        self.0.value().map(|v| {
            let bi_v = fe_to_big(*v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from(255u8));
            Byte(bi_v.to_bytes_le().first().copied().unwrap_or(0u8))
        })
    }

    fn cell(&self) -> Cell {
        self.0.cell()
    }

    fn inner_value(&self) -> AssignedNative<F> {
        self.0.clone()
    }
}

#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedBit<F: PrimeField>(pub AssignedNative<F>);

impl<F: PrimeField> AssignedElement<F> for AssignedBit<F> {
    type Element = F;

    fn new(value: AssignedNative<F>) -> Self {
        Self { 0: value }
    }

    fn value(&self) -> Value<F> {
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

    fn cell(&self) -> Cell {
        self.0.cell()
    }

    fn inner_value(&self) -> AssignedNative<F> {
        self.0.clone()
    }
}

#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedBlake2bWord<F: PrimeField>(pub AssignedNative<F>);

impl<F: PrimeField> AssignedElement<F> for AssignedBlake2bWord<F> {
    type Element = Blake2bWord;

    fn new(value: AssignedNative<F>) -> Self {
        Self { 0: value }
    }

    fn value(&self) -> Value<Blake2bWord> {
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

    fn cell(&self) -> Cell {
        self.0.cell()
    }

    fn inner_value(&self) -> AssignedNative<F> {
        self.0.clone()
    }
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

pub struct AssignedRow<F: PrimeField> {
    pub full_number: AssignedBlake2bWord<F>,
    pub limbs: [AssignedByte<F>; 8],
}

impl<F: PrimeField> AssignedRow<F> {
    pub fn new(full_number: AssignedBlake2bWord<F>, limbs: [AssignedByte<F>; 8]) -> Self {
        Self { full_number, limbs }
    }

    pub fn new_from_native(row: [AssignedNative<F>; 9]) -> Self {
        let full_number = AssignedBlake2bWord::<F>::new(row[0].clone());
        let limbs = row[1..].iter().map(|byte|
            AssignedByte::<F>::new(byte.clone())
        ).collect::<Vec<_>>();
        Self::new(full_number, limbs.try_into().unwrap())
    }
}

