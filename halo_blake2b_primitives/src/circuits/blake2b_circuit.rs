use super::*;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use std::array;

pub struct Blake2bCircuit<F: Field, const BLOCKS: usize> {
    _ph: PhantomData<F>,
    output_size: Value<F>,
    input: [[Value<F>; 16]; BLOCKS],
    input_size: Value<F>,
}

#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
}

impl<F: PrimeField, const BLOCKS: usize> Circuit<F> for Blake2bCircuit<F, BLOCKS> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            output_size: Value::unknown(),
            input: [[Value::unknown(); 16]; BLOCKS],
            input_size: Value::unknown(),
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        meta.enable_equality(full_number_u64);

        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        for limb in limbs {
            meta.enable_equality(limb);
        }

        let carry = meta.advice_column();

        let blake2b_table16_chip =
            Blake2bTable16Chip::configure(meta, full_number_u64, limbs, carry);

        Self::Config {
            _ph: PhantomData,
            blake2b_table16_chip,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let output_size = self.output_size;
        let input_size = self.input_size;
        let input_blocks = self.input;

        config.blake2b_table16_chip.initialize_with(&mut layouter);
        config.blake2b_table16_chip.compute_blake2b_hash_for_inputs(
            &mut layouter,
            output_size,
            input_size,
            input_blocks,
        )
    }
}

impl<F: PrimeField, const BLOCKS: usize> Blake2bCircuit<F, BLOCKS> {
    #[allow(dead_code)]
    fn assert_cell_has_value(obtained_cell: AssignedCell<F, F>, expected_value: Value<F>) {
        obtained_cell.value().copied().and_then(|x| {
            expected_value.and_then(|y| {
                assert_eq!(x, y);
                Value::<F>::unknown()
            })
        });
    }

    #[allow(dead_code)]
    fn assert_state_is_correct(state: &[AssignedCell<F, F>; 16], desired_state: [Value<F>; 16]) {
        for i in 0..16 {
            Self::assert_cell_has_value(state[i].clone(), desired_state[i]);
        }
    }

    pub fn new_for(
        output_size: Value<F>,
        input: [[Value<F>; 16]; BLOCKS],
        input_size: Value<F>,
    ) -> Self {
        Self {
            _ph: PhantomData,
            output_size,
            input,
            input_size,
        }
    }
}
