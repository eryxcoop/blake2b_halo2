use super::*;
use std::array;

pub struct AdditionMod64Circuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 6]; 3],
}

impl<F: Field> AdditionMod64Circuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 6]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: Field + From<u64>> Circuit<F> for AdditionMod64Circuit<F> {
    type Config = AdditionMod64Chip<F>; // TODO: there should be a wrapper for this, not using directly the chip
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: AdditionMod64Chip::unknown_trace(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 4] = array::from_fn(|_| meta.advice_column());
        let carry = meta.advice_column();
        let decompose_16_chip = Decompose16Chip::configure(meta, full_number_u64, limbs);

        AdditionMod64Chip::configure(meta, decompose_16_chip, full_number_u64, carry)
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .decompose_16_chip
            .populate_lookup_table16(&mut layouter)?;
        config.assign_addition_rows(&mut layouter, self.trace);
        Ok(())
    }
}
