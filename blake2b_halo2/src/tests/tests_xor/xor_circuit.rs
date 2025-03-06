use super::*;
use crate::chips::decompose_8::Decompose8Config;
use crate::chips::xor_table::XorTableConfig;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct XorConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    xor_config: XorTableConfig<F>,
    decompose_8_config: Decompose8Config<F>,
}

pub struct XorCircuit<F: PrimeField> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 3],
}

impl<F: PrimeField> XorCircuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 9]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for XorCircuit<F> {
    type Config = XorConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: XorTableConfig::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs_8_bits: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs_8_bits);
        let xor_config = XorTableConfig::configure(meta, limbs_8_bits);

        Self::Config {
            _ph: PhantomData,
            xor_config,
            decompose_8_config,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_config.populate_lookup_table(&mut layouter)?;

        config.xor_config.populate_xor_lookup_table(&mut layouter)?;
        config.xor_config.populate_xor_region(
            &mut layouter,
            self.trace,
            &mut config.decompose_8_config,
        )
    }
}
