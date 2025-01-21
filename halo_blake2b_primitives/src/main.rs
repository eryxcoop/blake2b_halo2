use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem},
};

use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::decompose_16_chip::Decompose16Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::rotate_24_chip::Rotate24Chip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use crate::chips::xor_chip::XorChip;
use ff::Field;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

pub mod auxiliar_functions;
pub mod chips;
#[cfg(test)]
pub mod tests;

struct Blake2bCircuit<F: Field> {
    _ph: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct Blake2bConfig<F: Field + Clone> {
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Circuit<F> for Blake2bCircuit<F> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Blake2bCircuit::new_for_unknown_values()
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {

        Blake2bConfig {
            _ph: PhantomData,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        Ok(())
    }
}

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn new_for_unknown_values() -> Self {
        Blake2bCircuit {
            _ph: PhantomData,
        }
    }
}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;
    let circuit = Blake2bCircuit::<Fr>::new_for_unknown_values();
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
