use std::marker::PhantomData;

use halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use crate::chips::decomposition_trait::Decomposition;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, Fixed};
use halo2_proofs::dev::MockProver;

pub mod auxiliar_functions;
pub mod chips;

#[cfg(test)]
pub mod tests;
