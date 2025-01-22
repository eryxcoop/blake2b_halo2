use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::generic_limb_rotation_chip::LimbRotationChip;
use ff::PrimeField;
use std::array;

#[derive(Clone)]
pub struct LimbRotationConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    decompose_8_chip: Decompose8Chip<F>,
    limb_rotation_chip: LimbRotationChip<F>,
}

#[derive(Clone)]
pub struct LimbRotationCircuit<F: PrimeField, const T: usize> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 2],
}

impl<F: PrimeField, const T: usize> LimbRotationCircuit<F, T> {
    pub fn new_for_trace(trace: [[Value<F>; 9]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField, const T: usize> Circuit<F> for LimbRotationCircuit<F, T> {
    type Config = LimbRotationConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: LimbRotationChip::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);

        let limb_rotation_chip = LimbRotationChip::new();

        Self::Config {
            _ph: PhantomData,
            decompose_8_chip,
            limb_rotation_chip,
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let limbs_to_rotate_to_the_right = match T {
            32 => 4,
            24 => 5,
            16 => 6,
            _ => panic!("Unexpected Rotation"),
        };

        config
            .decompose_8_chip
            .populate_lookup_table(&mut layouter)?;
        config.limb_rotation_chip.assign_rotation_rows(
            &mut layouter,
            &mut config.decompose_8_chip,
            self.trace,
            limbs_to_rotate_to_the_right,
        );

        Ok(())
    }
}
