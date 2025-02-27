#![allow(unused_doc_comments)]

use std::marker::PhantomData;

use halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use crate::chips::decomposition_trait::Decomposition;
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
