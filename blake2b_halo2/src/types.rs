use std::fmt::Debug;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Value};
use num_bigint::BigUint;

/// The inner type of AssignedByte.
// A wrapper around `u8` to have a type that we own and for which we can implement some necessary
// traits like `From<u64>`.
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

#[derive(Copy, Clone, Debug)]
pub struct Blake2bWord(pub u64);

pub type AssignedNative<F> = AssignedCell<F, F>;

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
            Byte(bi_v.to_bytes_le().first().copied().unwrap_or(0u8))
        })
    }
}

#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedBlake2bWord<F: PrimeField>(AssignedNative<F>);

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
            let first_8_bytes: [u8; 8] = bi_v.to_bytes_le()[..8].try_into().unwrap();
            Blake2bWord(u64::from_le_bytes(first_8_bytes))
        })
    }
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

/// Trait for accessing the value inside assigned circuit elements.
pub trait AssignedElement<F: PrimeField>: Clone + Debug {
    /// Represents the unassigned type corresponding to the [midnight_circuits::types::InnerValue]
    type Element: Clone + Debug;

    //constructor
    fn new(value: AssignedNative<F>) -> Self;

    /// Returns the value of the assigned element.
    fn value(&self) -> Value<Self::Element>;
}

pub struct Row8Limbs<F: PrimeField> {
    full_number: AssignedBlake2bWord<F>,
    limbs: Vec<AssignedByte<F>>,
}

impl<F: PrimeField> Row8Limbs<F> {
    pub fn new(full_number: AssignedBlake2bWord<F>, limbs: Vec<impl AssignedElement<F>>) -> Self {
        #[cfg(not(test))]
        assert!(limbs.len() == 8);
        Self { full_number, limbs }
    }
}

pub struct Row4Limbs<F: PrimeField> {
    full_number: AssignedBlake2bWord<F>,
    limbs: Vec<AssignedNative<F>>,
}

impl<F: PrimeField> Row4Limbs<F> {
    pub fn new(full_number: AssignedBlake2bWord<F>, limbs: Vec<impl AssignedElement<F>>) -> Self {
        #[cfg(not(test))]
        assert!(limbs.len() == 4);
        Self { full_number, limbs }
    }
}

pub trait RowLimb <F: PrimeField> {
    fn full_number(&self) -> AssignedBlake2bWord<F>;
    fn limbs(&self) -> Vec<impl AssignedElement<F>>;
}

impl<F: PrimeField> RowLimb<F> for Row8Limbs<F> {
    fn full_number(&self) -> AssignedBlake2bWord<F> {
        self.full_number
    }

    fn limbs(&self) -> Vec<impl AssignedElement<F>> {
        self.limbs.clone()
    }
}

