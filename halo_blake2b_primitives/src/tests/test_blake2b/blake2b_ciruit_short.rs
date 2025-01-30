use super::*;
use std::array;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, Fixed};
use crate::chips::blake2b_table16_chip::{Blake2bTable16Chip, Operand};

pub struct Blake2bCircuitShort<F: Field> {
    _ph: PhantomData<F>,
    output_size: Value<F>,
    input: [Value<F>; 16],
}

#[derive(Clone)]
pub struct Blake2bShortConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
    iv_constants: Column<Fixed>
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

        let blake2b_table16_chip = Blake2bTable16Chip::configure(
            meta, full_number_u64, limbs, carry
        );

        let iv_constants = meta.fixed_column();
        meta.enable_equality(iv_constants);

        Self::Config {
            _ph: PhantomData,
            blake2b_table16_chip,
            iv_constants
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
            config.blake2b_table16_chip.new_row_for(input, &mut layouter).unwrap()
        });

        let constants = Self::IV_CONSTANTS();
        let iv_constants: [AssignedCell<F, F>; 8] = constants.iter().enumerate().map(|(i, value)| {
            layouter.assign_region(
                || "row",
                |mut region| {
                    region.assign_fixed(|| "iv constants", config.iv_constants, i, || *value)
                }).unwrap()
        }).collect::<Vec<AssignedCell<F, F>>>().try_into().unwrap();;


        let mut iv_constants_doubled: [Value<F>; 16] = [Value::known(F::ZERO); 16];
        iv_constants_doubled[..8].copy_from_slice(&constants);
        iv_constants_doubled[8..].copy_from_slice(&constants);


        let state = iv_constants_doubled.map(|constant| {
            config.blake2b_table16_chip.new_row_for(constant, &mut layouter).unwrap()
        });

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
    fn assert_values_are_equal(
        obtained_value: Operand<F>,
        expected_value: Value<F>,
    ) {
        match obtained_value {
            Operand::Cell(cell) => {
                cell.value().cloned().and_then(|x| {
                    expected_value.and_then(|y| {
                        assert_eq!(x, y);
                        Value::<F>::unknown()
                    })
                });
            },
            _ => {}
        }
        // obtained_value.and_then(|x| {
        //     expected_value.and_then(|y| {
        //         assert_eq!(x, y);
        //         Value::<F>::unknown()
        //     })
        // });
    }

    pub fn new_for(
        output_size: Value<F>,
        input: [Value<F>; 16],
    ) -> Self {
        Self {
            _ph: PhantomData,
            output_size,
            input,
        }
    }
}
