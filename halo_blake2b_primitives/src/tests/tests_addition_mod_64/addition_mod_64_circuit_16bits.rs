use super::*;
use crate::chips::addition_mod_64_chip::AdditionMod64Chip;
use crate::chips::decompose_16_chip::Decompose16Chip;
use std::array;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;

#[derive(Clone)]
pub struct AdditionMod64Config16Bits<F: Field> {
    addition_mod_64_chip: AdditionMod64Chip<F, 4, 6>,
    decompose_16_chip: Decompose16Chip<F>,
}

pub struct AdditionMod64Circuit16Bits<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 6]; 3],
}

impl<F: Field> AdditionMod64Circuit16Bits<F> {
    pub fn new_for_trace(trace: [[Value<F>; 6]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for AdditionMod64Circuit16Bits<F> {
    type Config = AdditionMod64Config16Bits<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: [[Value::unknown(); 6]; 3],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 4] = array::from_fn(|_| meta.advice_column());
        let carry = meta.advice_column();

        let decompose_16_chip = Decompose16Chip::configure(meta, full_number_u64, limbs);
        let addition_mod_64_chip =
            AdditionMod64Chip::<F, 4, 6>::configure(meta, full_number_u64, carry);

        Self::Config {
            addition_mod_64_chip,
            decompose_16_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .decompose_16_chip
            .populate_lookup_table(&mut layouter)?;
        config.addition_mod_64_chip.populate_addition_rows(
            &mut layouter,
            self.trace,
            &mut config.decompose_16_chip,
        );
        Ok(())
    }
}
