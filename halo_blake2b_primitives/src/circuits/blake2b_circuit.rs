use super::*;
use crate::auxiliar_functions::*;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, Fixed, Instance};
use std::array;

pub struct Blake2bCircuit<F: Field, const R: usize> {
    _ph: PhantomData<F>,
    output_size: Value<F>,
    input: [Value<F>; R],
    input_size: Value<F>,
}

#[derive(Clone)]
pub struct Blake2bConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
    pub constants: Column<Fixed>,
    expected_final_state: Column<Instance>,
}

impl<F: PrimeField, const R: usize> Circuit<F> for Blake2bCircuit<F, R> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            output_size: Value::unknown(),
            input: [Value::unknown(); R],
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

        let constants = meta.fixed_column();
        meta.enable_equality(constants);

        let expected_final_state = meta.instance_column();
        meta.enable_equality(expected_final_state);

        Self::Config {
            _ph: PhantomData,
            blake2b_table16_chip,
            constants,
            expected_final_state,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.blake2b_table16_chip.initialize_with(&mut layouter);

        // Initialize constants that will be used for state
        let constants = Blake2bTable16Chip::iv_constants();
        let iv_constants: [AssignedCell<F, F>; 8] = Blake2bTable16Chip::assign_iv_constants_to_fixed_cells(&mut config, &mut layouter, constants);
        let init_const_state_0 = Blake2bTable16Chip::assign_01010000_constant_to_fixed_cell(&mut config, &mut layouter)?;
        let output_size_constant = Blake2bTable16Chip::assign_output_size_to_fixed_cell(&mut config, &mut layouter, self.output_size)?;
        let mut global_state = config.blake2b_table16_chip.compute_initial_state(&mut layouter,
                                                       constants, &iv_constants, init_const_state_0, output_size_constant)?;

        //TODO split input in blocks and call compress for each block
        let mut blocks: Vec<[Value<F>; 16]> = Vec::new();
        let block_aux: [Value<F>; 16] = self.input[0..16].try_into().unwrap();
        blocks.push(block_aux);

        let block = blocks[0];

        config.blake2b_table16_chip.compress(
            &mut layouter,
            &iv_constants,
            &mut global_state,
            block,
            self.input_size,
        )?;

        for i in 0..8 {
            layouter.constrain_instance(global_state[i].cell(), config.expected_final_state, i)?;
        }

        Ok(())
    }
}

impl<F: PrimeField, const R: usize> Blake2bCircuit<F, R> {

    fn _assert_state_is_correct(state: &[AssignedCell<F, F>; 16], desired_state: [Value<F>; 16]) {
        for i in 0..16 {
            Self::assert_cell_has_value(state[i].clone(), desired_state[i]);
        }
    }

    #[allow(dead_code)]
    fn assert_cell_has_value(obtained_cell: AssignedCell<F, F>, expected_value: Value<F>) {
        obtained_cell.value().copied().and_then(|x| {
            expected_value.and_then(|y| {
                assert_eq!(x, y);
                Value::<F>::unknown()
            })
        });
    }

    pub fn new_for(output_size: Value<F>, input: [Value<F>; R], input_size: Value<F>) -> Self {
        Self {
            _ph: PhantomData,
            output_size,
            input,
            input_size,
        }
    }
}
