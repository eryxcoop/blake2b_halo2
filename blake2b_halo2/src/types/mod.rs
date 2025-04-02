/// This module holds types that exist to enforce safety across our code. The main types are:
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
/// a context where its value has been constrained by a circuit restriction to be in range.
///
/// Everytime you see an AssignedBit, AssignedByte, AssignedBlake2bWord or AssignedRow,
/// you can be certain that all their values were range checked (both in the synthesize and in the
/// circuit constraints)

use ff::PrimeField;
use halo2_proofs::circuit::AssignedCell;
use num_bigint::BigUint;

/// Native type for an [AssignedCell] that hasn't been constrained yet
pub(crate) type AssignedNative<F> = AssignedCell<F, F>;

pub(crate) mod bit;
pub(crate) mod byte;
pub(crate) mod blake2b_word;
pub(crate) mod row;


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

