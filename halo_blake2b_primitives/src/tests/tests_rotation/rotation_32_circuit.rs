use std::array;
use ff::PrimeField;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::rotate_32_chip::Rotate32Chip;
use super::*;

#[derive(Clone)]
pub struct Rotation32Config<F: Field> {
    _ph: PhantomData<F>,
    decompose_8_chip: Decompose8Chip<F>,
    rotation_32_chip: Rotate32Chip<F>
}

#[derive(Clone)]
pub struct Rotation32Circuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 2]
}


impl<F: Field> Rotation32Circuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 9]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for Rotation32Circuit<F> {
    type Config = Rotation32Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: Rotate32Chip::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let t_range8 = meta.lookup_table_column();
        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs, t_range8);

        let rotation_32_chip = Rotate32Chip::new();

        Self::Config {
            _ph: PhantomData,
            decompose_8_chip,
            rotation_32_chip
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_chip.populate_lookup_table8(&mut layouter)?;
        config.rotation_32_chip.assign_rotation_rows(
            &mut layouter,
            &mut config.decompose_8_chip,
            self.trace,
        );

        Ok(())
    }
}
