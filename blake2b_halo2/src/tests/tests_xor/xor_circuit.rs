use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::xor_chip::XorChip;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct XorConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    xor_chip: XorChip<F>,
    decompose_8_chip: Decompose8Chip<F>,
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
            trace: XorChip::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs_8_bits: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs_8_bits);
        let xor_chip = XorChip::configure(meta, limbs_8_bits);

        Self::Config {
            _ph: PhantomData,
            xor_chip,
            decompose_8_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_chip.populate_lookup_table(&mut layouter)?;

        config.xor_chip.populate_xor_lookup_table(&mut layouter)?;
        config.xor_chip.populate_xor_region(
            &mut layouter,
            self.trace,
            &mut config.decompose_8_chip,
        );

        Ok(())
    }
}
