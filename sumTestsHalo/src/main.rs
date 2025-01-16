use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{self, Circuit, ConstraintSystem},
};

use ff::Field;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;
use crate::chips::decompose_16_chip::Decompose16Chip;
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::xor_chip::XorChip;

struct Blake2bCircuit<F: Field> {
    _ph: PhantomData<F>,
    addition_trace: [[Value<F>; 6]; 3],
    rotation_trace_63: [[Value<F>; 5]; 2],
    rotation_trace_24: [[Value<F>; 5]; 3],
    xor_trace: [[Value<F>; 9]; 3],
    should_create_xor_table: bool,
}

#[derive(Clone, Debug)]
struct Blake2bConfig<F: Field + Clone> {
    full_number_u64: Column<Advice>,

    // Working with 4 limbs of u16
    limbs: [Column<Advice>; 4],
    carry: Column<Advice>,
    q_add: Selector,
    t_range16: TableColumn,
    t_range8: TableColumn,
    q_rot63: Selector,
    q_rot24: Selector,
    decompose_16_chip: Decompose16Chip<F>,

    // Working with 8 limbs of u8
    limbs_8_bits: [Column<Advice>; 8],
    xor_chip: XorChip<F>,
    decompose_8_chip: Decompose8Chip<F>,

    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Circuit<F> for Blake2bCircuit<F> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Blake2bCircuit::new_for_unknown_values()
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Addition
        let q_add = meta.complex_selector();

        let full_number_u64 = meta.advice_column();
        let limbs = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for limb in limbs {
            meta.enable_equality(limb);
        }
        let t_range16 = meta.lookup_table_column();
        let t_range8 = meta.lookup_table_column();
        let carry = meta.advice_column();

        let decompose_16_chip = Decompose16Chip::configure(meta, full_number_u64, limbs, t_range16);

        meta.create_gate("sum mod 2 ^ 64", |meta| {
            let q_add = meta.query_selector(q_add);
            let full_number_x = meta.query_advice(full_number_u64, Rotation(0));
            let full_number_y = meta.query_advice(full_number_u64, Rotation(1));
            let full_number_result = meta.query_advice(full_number_u64, Rotation(2));

            let carry = meta.query_advice(carry, Rotation(2));
            // TODO check if x, y and result are 64 bits
            vec![
                q_add
                    * (full_number_result - full_number_x - full_number_y
                        + carry
                            * (Expression::Constant(F::from(((1u128 << 64) - 1) as u64))
                                + Expression::Constant(F::ONE))),
            ]
        });

        for limb in limbs {
            Self::range_check_for_limb_16_bits(meta, &limb, &decompose_16_chip.q_decompose, &t_range16);
        }

        // Rotation
        let q_rot63 = meta.complex_selector();
        meta.create_gate("rotate right 63", |meta| {
            let q_rot63 = meta.query_selector(q_rot63);
            let input_full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let output_full_number = meta.query_advice(full_number_u64, Rotation::next());
            vec![
                q_rot63
                    * (Expression::Constant(F::from(2)) * input_full_number.clone()
                        - output_full_number.clone())
                    * (Expression::Constant(F::from(2)) * input_full_number
                        - output_full_number
                        - Expression::Constant(F::from(((1u128 << 64) - 1) as u64))),
            ]
        });

        // Rotation
        // 0 = (x*2^40 + z) - z*2^64 - y
        let q_rot24 = meta.complex_selector();
        meta.create_gate("rotate right 24", |meta| {
            let q_rot24 = meta.query_selector(q_rot24);
            let input_full_number = meta.query_advice(full_number_u64, Rotation(0));
            let chunk = meta.query_advice(full_number_u64, Rotation(1));
            let output_full_number = meta.query_advice(full_number_u64, Rotation(2));
            vec![
                q_rot24
                    * (Expression::Constant(F::from((1u128 << 40) as u64))
                        * input_full_number.clone()
                        + chunk.clone()
                        - Expression::Constant(F::from((1u128 << 63) as u64) * F::from(2))
                            * chunk.clone()
                        - output_full_number.clone()),
            ]
        });

        meta.lookup("lookup rotate_24 chunks", |meta| {
            let limb: Expression<F> = meta.query_advice(limbs[2], Rotation(1));
            let q_rot24 = meta.query_selector(q_rot24);
            vec![(q_rot24 * limb, t_range8)]
        });

        // config for xor
        let limbs_8_bits = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];


        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs_8_bits, t_range8);
        let xor_chip = XorChip::configure(meta, limbs_8_bits, decompose_8_chip.clone(), full_number_u64);

        Blake2bConfig {
            _ph: PhantomData,
            decompose_8_chip,
            decompose_16_chip,
            xor_chip,
            q_add,
            full_number_u64,
            limbs,
            t_range16,
            t_range8,
            carry,
            q_rot63,
            q_rot24,
            limbs_8_bits,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        self.assign_addition_rows(&mut config, &mut layouter);

        Self::populate_lookup_table16(&config, &mut layouter)?;

        // Rotation
        self.assign_rotation_rows(&mut config, &mut layouter);
        let _ = layouter.assign_region(
            || "rotate 24",
            |mut region| {
                let _ = config.q_rot24.enable(&mut region, 0);

                let mut first_row = self.rotation_trace_24[0].to_vec();
                first_row.push(Value::known(F::ZERO));
                let mut second_row = self.rotation_trace_24[1].to_vec();
                second_row.push(Value::known(F::ZERO));
                let mut third_row = self.rotation_trace_24[2].to_vec();
                third_row.push(Value::known(F::ZERO));
                Self::assign_row_from_values(&mut config, &mut region, first_row, 0);
                Self::assign_row_from_values(&mut config, &mut region, second_row, 1);
                Self::assign_row_from_values(&mut config, &mut region, third_row, 2);
                Ok(())
            },
        );

        Self::populate_lookup_table8(&config, &mut layouter)?;

        // XOR operation

        if self.should_create_xor_table {
            config.xor_chip.populate_xor_lookup_table(&mut layouter)?;
            config.xor_chip.create_xor_region(&mut layouter, self.xor_trace);
        }

        Ok(())
    }
}

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn assign_rotation_rows(&self, config: &mut Blake2bConfig<F>, layouter: &mut impl Layouter<F>) {
        let _ = layouter.assign_region(
            || "rotate 63",
            |mut region| {
                let _ = config.q_rot63.enable(&mut region, 0);

                let mut first_row = self.rotation_trace_63[0].to_vec();
                first_row.push(Value::known(F::ZERO));
                let mut second_row = self.rotation_trace_63[1].to_vec();
                second_row.push(Value::known(F::ZERO));
                Self::assign_row_from_values(config, &mut region, first_row, 0);
                Self::assign_row_from_values(config, &mut region, second_row, 1);
                Ok(())
            },
        );
    }

    fn assign_addition_rows(&self, config: &mut Blake2bConfig<F>, layouter: &mut impl Layouter<F>) {
        let _ = layouter.assign_region(
            || "decompose",
            |mut region| {
                let _ = config.q_add.enable(&mut region, 0);

                Self::assign_row_from_values(
                    config,
                    &mut region,
                    self.addition_trace[0].to_vec(),
                    0,
                );
                Self::assign_row_from_values(
                    config,
                    &mut region,
                    self.addition_trace[1].to_vec(),
                    1,
                );
                Self::assign_row_from_values(
                    config,
                    &mut region,
                    self.addition_trace[2].to_vec(),
                    2,
                );
                Ok(())
            },
        );
    }

    fn populate_lookup_table16(
        config: &Blake2bConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let table_name = "range 16bit check table";
        let max_value = 1 << 16;
        let lookup_column = config.t_range16;
        Self::check_lookup_table(layouter, lookup_column, table_name, max_value)?;

        Ok(())
    }

    fn populate_lookup_table8(
        config: &Blake2bConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let table_name = "range 8bit check table";
        let max_value = 1 << 8;
        let lookup_column = config.t_range8;

        Self::check_lookup_table(layouter, lookup_column, table_name, max_value)?;
        Ok(())
    }

    fn check_lookup_table(
        layouter: &mut impl Layouter<F>,
        lookup_column: TableColumn,
        table_name: &str,
        max_value: usize,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || table_name,
            |mut table| {
                // assign the table
                for i in 0..max_value {
                    table.assign_cell(
                        || "value",
                        lookup_column,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn _unknown_trace_for_rotation_63() -> [[Value<F>; 5]; 2] {
        [[Value::unknown(); 5]; 2]
    }

    fn _unknown_trace_for_addition() -> [[Value<F>; 6]; 3] {
        [[Value::unknown(); 6]; 3]
    }

    fn _unknown_trace_for_rotation_24() -> [[Value<F>; 5]; 3] {
        [[Value::unknown(); 5]; 3]
    }

    fn _unknown_trace_for_xor() -> [[Value<F>; 9]; 3] {
        [[Value::unknown(); 9]; 3]
    }

    fn new_for_unknown_values() -> Self {
        Blake2bCircuit {
            _ph: PhantomData,
            addition_trace: Self::_unknown_trace_for_addition(),
            rotation_trace_63: Self::_unknown_trace_for_rotation_63(),
            rotation_trace_24: Self::_unknown_trace_for_rotation_24(),
            xor_trace: Self::_unknown_trace_for_xor(),
            should_create_xor_table: false,
        }
    }

    fn range_check_for_limb_16_bits(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_decompose: &Selector,
        t_range16: &TableColumn,
    ) {
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_decompose = meta.query_selector(*q_decompose);
            vec![(q_decompose * limb, *t_range16)]
        });
    }

    fn assign_row_from_values(
        config: &mut Blake2bConfig<F>,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) {
        let _ = config.decompose_16_chip.assign_16bit_row_from_values(region, row.clone(), offset);

        let _ = region.assign_advice(|| "carry", config.carry, offset, || row[5]);
    }

}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;
    let circuit = Blake2bCircuit::<Fr>::new_for_unknown_values();
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

pub mod auxiliar_functions;
#[cfg(test)]
pub mod tests;
pub mod chips;
