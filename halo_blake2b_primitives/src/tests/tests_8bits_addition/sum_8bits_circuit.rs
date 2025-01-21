use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::sum_8bits_chip::Sum8BitsChip;
use std::array;

pub struct Sum8BitsTestCircuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 10]; 3],
}

#[derive(Clone, Debug)]
pub struct Sum8BitsTestConfig<F: Field + Clone> {
    sum_8bits_chip: Sum8BitsChip<F>,
    decompose_8_chip: Decompose8Chip<F>,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Circuit<F> for Sum8BitsTestCircuit<F> {
    type Config = Sum8BitsTestConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: [[Value::unknown(); 10]; 3],
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        let carry = meta.advice_column();

        let t_range8 = meta.lookup_table_column();
        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs, t_range8);

        let sum_8bits_chip =
            Sum8BitsChip::configure(meta, decompose_8_chip.clone(), full_number_u64, carry);

        Self::Config {
            _ph: PhantomData,
            decompose_8_chip,
            sum_8bits_chip,
        }
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
        config.sum_8bits_chip.assign_addition_rows(
            &mut layouter,
            self.trace,
            &mut config.decompose_8_chip,
        );
        Ok(())
    }
}

impl<F: Field> Sum8BitsTestCircuit<F> {
    pub fn new_for_trace(trace: [[Value<F>; 10]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}
