use super::*;
use crate::chips::decompose_16_chip::Decompose16Chip;
use crate::chips::rotate_63_chip::Rotate63Chip;
use std::array;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Rotation63Config<F: Field> {
    _ph: PhantomData<F>,
    rotation_63_chip: Rotate63Chip<F>,
    decompose_16_chip: Decompose16Chip<F>,
}

pub struct Rotation63Circuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 5]; 2],
}

impl<F: Field> Rotation63Circuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 5]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for Rotation63Circuit<F> {
    type Config = Rotation63Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: Rotate63Chip::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs_4_bits: [Column<Advice>; 4] = array::from_fn(|_| meta.advice_column());

        let decompose_16_chip = Decompose16Chip::configure(meta, full_number_u64, limbs_4_bits);

        let rotation_63_chip = Rotate63Chip::configure(meta, full_number_u64);

        Self::Config {
            _ph: PhantomData,
            decompose_16_chip,
            rotation_63_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .decompose_16_chip
            .populate_lookup_table(&mut layouter)?;
        config.rotation_63_chip.assign_rotation_rows(
            &mut layouter,
            &mut config.decompose_16_chip.clone(),
            self.trace,
        );

        Ok(())
    }
}
