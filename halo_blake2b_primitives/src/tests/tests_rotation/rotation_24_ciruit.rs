use super::*;
use crate::chips::decompose_16_chip::Decompose16Chip;
use crate::chips::rotate_24_chip::Rotate24Chip;
use std::array;
use std::marker::PhantomData;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;

#[derive(Clone)]
pub struct Rotation24Config<F: PrimeField> {
    _ph: PhantomData<F>,
    rotation_24_chip: Rotate24Chip<F>,
    decompose_16_chip: Decompose16Chip<F>,
}

pub struct Rotation24Circuit<F: PrimeField> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 5]; 3],
}

impl<F: PrimeField> Rotation24Circuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 5]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for Rotation24Circuit<F> {
    type Config = Rotation24Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: Rotate24Chip::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs_4_bits: [Column<Advice>; 4] = array::from_fn(|_| meta.advice_column());

        let decompose_16_chip = Decompose16Chip::configure(meta, full_number_u64, limbs_4_bits);

        let rotation_24_chip = Rotate24Chip::configure(meta, full_number_u64, limbs_4_bits);

        Self::Config {
            _ph: PhantomData,
            rotation_24_chip,
            decompose_16_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .decompose_16_chip
            .populate_lookup_table(&mut layouter)?;

        config
            .rotation_24_chip
            .populate_lookup_table8(&mut layouter);

        config.rotation_24_chip.assign_rotation_rows(
            &mut layouter,
            &mut config.decompose_16_chip,
            self.trace,
        );

        Ok(())
    }
}
