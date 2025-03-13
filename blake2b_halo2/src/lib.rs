#![allow(unused_doc_comments)]

use std::marker::PhantomData;

use halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use crate::base_operations::decomposition::Decomposition;
use ff::{PrimeField, Field};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

pub mod auxiliar_functions;
pub mod base_operations;

#[cfg(test)]
pub mod tests;
pub mod blake2b;
pub mod example_blake2b_circuit;
