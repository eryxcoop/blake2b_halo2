#![allow(unused_doc_comments)]

use std::marker::PhantomData;

use halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use crate::chips::decomposition::Decomposition;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

pub mod auxiliar_functions;
pub mod chips;
pub mod circuits;

#[cfg(test)]
pub mod tests;
pub mod circuit_runner;

#[cfg(all(feature = "sum_with_4_limbs", feature = "sum_with_8_limbs"))]
compile_error!(
    "Features `sum_with_4_limbs` and `sum_with_8_limbs` cannot be enabled at the same time!"
);

#[cfg(all(feature = "xor_with_table", feature = "xor_with_spread"))]
compile_error!(
    "Features `xor_with_table` and `xor_with_spread` cannot be enabled at the same time!"
);
