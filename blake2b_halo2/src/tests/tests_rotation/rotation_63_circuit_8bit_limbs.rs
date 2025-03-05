use super::*;
use crate::chips::decompose_8::Decompose8Config;
use crate::chips::rotate_63_chip::Rotate63Chip;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use std::marker::PhantomData;

pub struct Rotation63Circuit8bitLimbs<F: PrimeField> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 2],
}

impl<F: PrimeField> Rotation63Circuit8bitLimbs<F> {
    pub fn new_for_trace(trace: [[Value<F>; 9]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for Rotation63Circuit8bitLimbs<F> {
    type Config = Rotation63Config8bitLimbs<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: Rotate63Chip::<F, 8, 9>::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs_8_bits: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_chip = Decompose8Config::configure(meta, full_number_u64, limbs_8_bits);

        let rotation_63_chip = Rotate63Chip::configure(meta, full_number_u64);

        Self::Config {
            _ph: PhantomData,
            decompose_8_chip,
            rotation_63_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_chip.populate_lookup_table(&mut layouter)?;
        config.rotation_63_chip.populate_rotation_rows(
            &mut layouter,
            &mut config.decompose_8_chip.clone(),
            self.trace,
        )
    }
}
