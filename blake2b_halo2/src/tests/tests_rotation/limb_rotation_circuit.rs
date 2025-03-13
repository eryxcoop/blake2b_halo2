use super::*;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use ff::PrimeField;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;

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
    type Config = LimbRotationCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: LimbRotation::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);

        Self::Config {
            _ph: PhantomData,
            decompose_8_config,
            limb_rotation_config: LimbRotation,
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let limbs_to_rotate_to_the_right = match T {
            32 => 4,
            24 => 3,
            16 => 2,
            _ => panic!("Unexpected Rotation"),
        };

        config.decompose_8_config.populate_lookup_table(&mut layouter)?;
        config.limb_rotation_config.populate_rotation_rows(
            &mut layouter,
            &mut config.decompose_8_config,
            self.trace,
            limbs_to_rotate_to_the_right,
        )
    }
}
