use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Value};
use num_bigint::BigUint;

/// The inner type of AssignedByte.
// A wrapper around `u8` to have a type that we own and for which we can implement some necessary
// traits like `From<u64>`.
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

#[derive(Copy, Clone, Debug)]
pub struct BlockWord(pub u64);

/// This wrapper type on `AssignedNative<F>` is designed to enforce type safety
/// on assigned bytes. It prevents the user from creating an `AssignedByte`
/// without using the designated entry points, which guarantee (with
/// constraints) that the assigned value is indeed in the range [0, 256).
#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedByte<F: PrimeField>(AssignedCell<F, F>);

impl<F: PrimeField> AssignedByte<F> {

    fn value(&self) -> Value<Byte> {
        self.0.value().map(|v| {
            let bi_v = fe_to_big(*v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from(255u8));
            Byte(bi_v.to_bytes_le().first().copied().unwrap_or(0u8))
        })
    }
}

#[derive(Clone, Debug)]
#[must_use]
pub struct AssignedU64<F: PrimeField>(AssignedCell<F, F>);

impl<F: PrimeField> AssignedU64<F> {
    fn value(&self) -> Value<BlockWord> {
        self.0.value().map(|v| {
            let bi_v = fe_to_big(*v);
            #[cfg(not(test))]
            assert!(bi_v <= BigUint::from((1u128 << 64) - 1));
            let first_8_bytes: [u8; 8] = bi_v.to_bytes_le()[0..8].iter().try_into().unwrap();
            BlockWord(u64::from_le_bytes(first_8_bytes))
        })
    }
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}