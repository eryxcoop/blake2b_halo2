use super::*;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, Fixed, Instance};
use std::array;

pub struct Blake2bCircuitShort<F: Field> {
    _ph: PhantomData<F>,
    output_size: Value<F>,
    input: [Value<F>; 16],
    input_size: Value<F>,
}

#[derive(Clone)]
pub struct Blake2bShortConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
    constants: Column<Fixed>,
    expected_final_state: Column<Instance>
}

impl<F: PrimeField> Circuit<F> for Blake2bCircuitShort<F> {
    type Config = Blake2bShortConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            output_size: Value::unknown(),
            input: [Value::unknown(); 16],
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

        let current_block_words = self.input.map(|input| {
            config
                .blake2b_table16_chip
                .new_row_from_value(input, &mut layouter)
                .unwrap()
        });

        let constants = Self::IV_CONSTANTS();
        let iv_constants: [AssignedCell<F, F>; 8] = constants
            .iter()
            .enumerate()
            .map(|(i, value)| {
                layouter
                    .assign_region(
                        || "row",
                        |mut region| {
                            region.assign_fixed(|| "iv constants", config.constants, i, || *value)
                        },
                    )
                    .unwrap()
            })
            .collect::<Vec<AssignedCell<F, F>>>()
            .try_into()
            .unwrap();

        let init_const_state_0 = layouter.assign_region(
            || "constant",
            |mut region| {
                region.assign_fixed(
                    || "state 0 xor",
                    config.constants,
                    8,
                    || value_for(0x01010000u64),
                )
            },
        )?;

        let output_size_constant = layouter.assign_region(
            || "output size",
            |mut region| {
                region.assign_fixed(
                    || "output size",
                    config.constants,
                    9,
                    || self.output_size,
                )
            },
        )?;

        let mut iv_constants_doubled: [Value<F>; 16] = [Value::known(F::ZERO); 16];
        iv_constants_doubled[..8].copy_from_slice(&constants);
        iv_constants_doubled[8..].copy_from_slice(&constants);

        let mut state = iv_constants_doubled.map(|constant| {
            config
                .blake2b_table16_chip
                .new_row_from_value(constant, &mut layouter)
                .unwrap()
        });

        // Set copy constraints to recently initialized state 
        layouter.assign_region(|| "iv copy constraints", |mut region| {
            for i in 0..8 {
                region.constrain_equal(iv_constants[i].cell(), state[i].cell())?;
                region.constrain_equal(iv_constants[i].cell(), state[i + 8].cell())?;
            }
            Ok(())
        })?;

        // state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        state[0] = config.blake2b_table16_chip.xor(
            state[0].clone(),
            init_const_state_0.clone(),
            &mut layouter,
        );
        state[0] = config.blake2b_table16_chip.xor(
            state[0].clone(),
            output_size_constant,
            &mut layouter,
        );

        let mut global_state: [AssignedCell<F,F>; 8] = array::from_fn(|i| state[i].clone());

        // This implementation is for single block input+key, so some values can be hardcoded

        // accumulative_state[12] ^= processed_bytes_count
        let processed_bytes_count = config
            .blake2b_table16_chip
            .new_row_from_value(self.input_size, &mut layouter)?;
        state[12] = config.blake2b_table16_chip.xor(
            state[12].clone(),
            processed_bytes_count.clone(),
            &mut layouter,
        );
        // accumulative_state[13] ^= ctx.processed_bytes_count[1]; This is 0 so we ignore it

        // accumulative_state[14] = !accumulative_state[14]
        state[14] = config
            .blake2b_table16_chip
            .not(state[14].clone(), &mut layouter);

        Self::_assert_state_is_correct_before_mixing(&state);

        for i in 0..12 {
            for j in 0..8 {
                config.blake2b_table16_chip.mix(
                    Self::ABCD[j][0], Self::ABCD[j][1],
                    Self::ABCD[j][2], Self::ABCD[j][3],
                    Self::SIGMA[i][2 * j], Self::SIGMA[i][2 * j + 1],
                    &mut state, &current_block_words, &mut layouter)?;
            }
        }

        for i in 0..8 {
            global_state[i] = config.blake2b_table16_chip.xor(global_state[i].clone(), state[i].clone(), &mut layouter);
            global_state[i] = config.blake2b_table16_chip.xor(global_state[i].clone(), state[i + 8].clone(), &mut layouter);
        }

        for i in 0..8 {
           layouter.constrain_instance(global_state[i].cell(), config.expected_final_state, i)?;
        }

        Ok(())
    }
}

impl<F: PrimeField> Blake2bCircuitShort<F> {
    const ABCD: [[usize; 4]; 8] = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];

    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];

    fn _assert_state_is_correct_before_mixing(state: &[AssignedCell<F, F>; 16]) {
        let desired_state = Self::desired_state_before_mixing();
        Self::_assert_state_is_correct(state, desired_state);
    }

    fn _assert_state_is_correct(state: &[AssignedCell<F, F>; 16], desired_state: [Value<F>; 16]) {
        for i in 0..16 {
            Self::assert_cell_has_value(state[i].clone(), desired_state[i]);
        }
    }

    fn IV_CONSTANTS() -> [Value<F>; 8] {
        [
            value_for(0x6A09E667F3BCC908u128),
            value_for(0xBB67AE8584CAA73Bu128),
            value_for(0x3C6EF372FE94F82Bu128),
            value_for(0xA54FF53A5F1D36F1u128),
            value_for(0x510E527FADE682D1u128),
            value_for(0x9B05688C2B3E6C1Fu128),
            value_for(0x1F83D9ABFB41BD6Bu128),
            value_for(0x5BE0CD19137E2179u128),
        ]
    }
}

impl<F: PrimeField> Blake2bCircuitShort<F> {
    fn desired_state_before_mixing() -> [Value<F>; 16] {
        [
            value_for(7640891576939301192u64),
            value_for(13503953896175478587u64),
            value_for(4354685564936845355u64),
            value_for(11912009170470909681u64),
            value_for(5840696475078001361u64),
            value_for(11170449401992604703u64),
            value_for(2270897969802886507u64),
            value_for(6620516959819538809u64),
            value_for(7640891576956012808u64),
            value_for(13503953896175478587u64),
            value_for(4354685564936845355u64),
            value_for(11912009170470909681u64),
            value_for(5840696475078001361u64),
            value_for(11170449401992604703u64),
            value_for(16175846103906665108u64),
            value_for(6620516959819538809u64)
        ]
    }

    fn assert_cell_has_value(obtained_cell: AssignedCell<F, F>, expected_value: Value<F>) {
        obtained_cell.value().copied().and_then(|x| {
            expected_value.and_then(|y| {
                assert_eq!(x, y);
                Value::<F>::unknown()
            })
        });
    }

    pub fn new_for(output_size: Value<F>, input: [Value<F>; 16], input_size: Value<F>) -> Self {
        Self {
            _ph: PhantomData,
            output_size,
            input,
            input_size,
        }
    }
}
