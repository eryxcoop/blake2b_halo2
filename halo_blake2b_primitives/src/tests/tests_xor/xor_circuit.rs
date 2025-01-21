use super::*;
use std::array;
use std::marker::PhantomData;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::xor_chip::XorChip;

#[derive(Clone)]
pub struct XorConfig<F: Field> {
    _ph: PhantomData<F>,
    xor_chip: XorChip<F>,
    decompose_8_chip: Decompose8Chip<F>
}

pub struct XorCircuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 3],
}

impl<F: Field> XorCircuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 9]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: Field + From<u64>> Circuit<F> for XorCircuit<F> {
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
        let t_range8 = meta.lookup_table_column();

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs_8_bits, t_range8);
        let xor_chip = XorChip::configure(meta, limbs_8_bits, decompose_8_chip.clone());

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
        config.decompose_8_chip.populate_lookup_table8(&mut layouter)?;

        config.xor_chip.populate_xor_lookup_table(&mut layouter)?;
        config.xor_chip.create_xor_region(&mut layouter, self.trace, &mut config.decompose_8_chip);

        Ok(())
    }
}
