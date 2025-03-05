use super::*;
use crate::chips::decompose_8_chip::Decompose8Chip;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use std::array;

pub struct AdditionMod64Circuit8Bits<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 10]; 3],
}

#[derive(Clone, Debug)]
pub struct AdditionMod64Config8Bits<F: PrimeField + Clone> {
    sum_8bits_chip: AdditionChipWith8Limbs<F>,
    decompose_8_chip: Decompose8Chip<F>,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for AdditionMod64Circuit8Bits<F> {
    type Config = AdditionMod64Config8Bits<F>;
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

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs);

        let sum_8bits_chip = AdditionChipWith8Limbs::<F>::configure(meta, full_number_u64, carry);

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
        config.decompose_8_chip.populate_lookup_table(&mut layouter)?;
        config.sum_8bits_chip.populate_addition_rows(
            &mut layouter,
            self.trace,
            &mut config.decompose_8_chip,
        )?;
        Ok(())
    }
}

impl<F: Field> AdditionMod64Circuit8Bits<F> {
    pub fn new_for_trace(trace: [[Value<F>; 10]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}
