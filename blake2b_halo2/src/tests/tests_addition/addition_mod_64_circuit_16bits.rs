use super::*;
use crate::base_operations::decompose_16::Decompose16Config;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use crate::base_operations::addition_mod_64::AdditionMod64Config;

#[derive(Clone)]
pub struct AdditionMod64Config16Bits {
    addition_mod_64_config: AdditionMod64Config<4, 6>,
    decompose_16_config: Decompose16Config,
}

pub struct AdditionMod64Circuit16Bits<F: PrimeField> {
    trace: [[Value<F>; 6]; 3],
}

impl<F: PrimeField> AdditionMod64Circuit16Bits<F> {
    pub fn new_for_trace(trace: [[Value<F>; 6]; 3]) -> Self {
        Self { trace }
    }
}

impl<F: PrimeField> Circuit<F> for AdditionMod64Circuit16Bits<F> {
    type Config = AdditionMod64Config16Bits;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            trace: [[Value::unknown(); 6]; 3],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 4] = array::from_fn(|_| meta.advice_column());

        let decompose_16_config = Decompose16Config::configure(meta, full_number_u64, limbs);
        let addition_mod_64_config =
            AdditionMod64Config::<4, 6>::configure(meta, full_number_u64, limbs[0]);

        Self::Config {
            addition_mod_64_config,
            decompose_16_config,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_16_config.populate_lookup_table(&mut layouter)?;
        config.addition_mod_64_config.populate_addition_rows(
            &mut layouter,
            self.trace,
            &config.decompose_16_config,
        )?;
        Ok(())
    }
}
