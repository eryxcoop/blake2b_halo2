use super::*;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, Fixed};
use std::array;

pub struct Blake2bCircuitShort<F: Field> {
    _ph: PhantomData<F>,
    output_size: Value<F>,
    input: [Value<F>; 16],
}

#[derive(Clone)]
pub struct Blake2bShortConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
    constants: Column<Fixed>,
}

impl<F: PrimeField> Circuit<F> for Blake2bCircuitShort<F> {
    type Config = Blake2bShortConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            output_size: Value::unknown(),
            input: [Value::unknown(); 16],
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

        Self::Config {
            _ph: PhantomData,
            blake2b_table16_chip,
            constants,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.blake2b_table16_chip.initialize_with(&mut layouter);

        let input_cells = self.input.map(|input| {
            config
                .blake2b_table16_chip
                .new_row_for(input, &mut layouter)
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

        let output_size_constant= layouter.assign_region(
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
                .new_row_for(constant, &mut layouter)
                .unwrap()
        });

        // Set copy constraints to recently initialized state 
        layouter.assign_region(|| "iv copy constraints", |mut region| {
            for i in 0..8 {
                region.constrain_equal(iv_constants[i].cell(), state[i].cell())?;
                region.constrain_equal(iv_constants[i].cell(), state[i+8].cell())?;
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

        // This implementation is for single block input+key, so some values can be hardcoded
        // accumulative_state[12] ^= 128; We put it in the trace
        let mut processed_bytes_count = config
            .blake2b_table16_chip
            .new_row_for(Value::known(F::from(128u64)), &mut layouter)?;
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

        let DESIRED_STATE = Self::desired_state();
        for i in 0..16 {
            Self::assert_cell_has_value(state[i].clone(), DESIRED_STATE[i]);
        }

        Ok(())
    }
}

impl<F: PrimeField> Blake2bCircuitShort<F> {
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
    fn desired_state() -> [Value<F>; 16] {
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

    pub fn new_for(output_size: Value<F>, input: [Value<F>; 16]) -> Self {
        Self {
            _ph: PhantomData,
            output_size,
            input,
        }
    }
}
