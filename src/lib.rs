//! Halo2 Blake2b implementation.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
// #![deny(rust_2018_idioms)]
use halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use ff::PrimeField;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

pub(crate) mod base_operations;

#[cfg(test)]
mod tests;
pub(crate) mod blake2b;
pub mod usage_utils;
