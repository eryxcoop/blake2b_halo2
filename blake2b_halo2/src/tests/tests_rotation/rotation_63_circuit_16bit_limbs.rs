use super::*;
use crate::base_operations::decompose_16::Decompose16Config;
use crate::base_operations::rotate_63::Rotate63Config;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Rotation63Config16bitLimbs<F: Field> {
    _ph: PhantomData<F>,
    rotation_63_config: Rotate63Config<F, 4, 5>,
    decompose_16_config: Decompose16Config<F>,
}

pub struct Rotation63Circuit16bitLimbs<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 5]; 2],
}

impl<F: Field> Rotation63Circuit16bitLimbs<F> {
    pub fn new_for_trace(trace: [[Value<F>; 5]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for Rotation63Circuit16bitLimbs<F> {
    type Config = Rotation63Config16bitLimbs<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: Rotate63Config::<F, 4, 5>::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs_4_bits: [Column<Advice>; 4] = array::from_fn(|_| meta.advice_column());

        let decompose_16_config = Decompose16Config::configure(meta, full_number_u64, limbs_4_bits);
        let rotation_63_config = Rotate63Config::configure(meta, full_number_u64);

        Self::Config {
            _ph: PhantomData,
            decompose_16_config,
            rotation_63_config,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_16_config.populate_lookup_table(&mut layouter)?;
        config.rotation_63_config.populate_rotation_rows(
            &mut layouter,
            &mut config.decompose_16_config.clone(),
            self.trace,
        )
    }
}
