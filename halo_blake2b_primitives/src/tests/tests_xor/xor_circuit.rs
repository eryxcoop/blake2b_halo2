use super::*;
use std::array;
use std::marker::PhantomData;

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
    type Config = XorChip<F>; // TODO: there should be a wrapper for this, not using directly the chip
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

        let decompose_8_chip =
            Decompose8Chip::configure(meta, full_number_u64, limbs_8_bits, t_range8);

        XorChip::configure(
            meta,
            limbs_8_bits,
            decompose_8_chip.clone(),
            full_number_u64,
        )
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .decompose_8_chip
            .populate_lookup_table8(&mut layouter)?;
        config.populate_xor_lookup_table(&mut layouter)?;
        config.create_xor_region(&mut layouter, self.trace);

        Ok(())
    }
}
