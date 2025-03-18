use super::*;
use crate::auxiliar_functions::*;
use halo2_proofs::halo2curves::bn256::Fr;
use ff::Field;
use std::marker::PhantomData;

mod test_blake2b;
mod test_negate;
mod tests_addition;
mod tests_rotation;
mod tests_xor;
