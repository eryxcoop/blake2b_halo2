use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{self, Circuit, ConstraintSystem},
};

use ff::Field;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

struct Blake2bCircuit<F: Field> {
    _ph: PhantomData<F>,
    addition_trace: [[Value<F>; 6]; 3],
    rotation_trace: [[Value<F>; 5]; 2],
}

#[derive(Clone, Debug)]
struct Blake2bConfig<F: Field + Clone> {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 4],
    carry: Column<Advice>,
    q_decompose: Selector,
    q_add: Selector,
    t_range16: TableColumn,
    q_rot63: Selector,
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
        let q_decompose = meta.complex_selector();
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
        let carry = meta.advice_column();

        meta.create_gate("decompose in 16bit words", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let limbs: Vec<Expression<F>> = limbs
                .iter()
                .map(|column| meta.query_advice(*column, Rotation::cur()))
                .collect();
            vec![
                q_decompose
                    * (full_number
                        - limbs[0].clone()
                        - limbs[1].clone() * Expression::Constant(F::from(1 << 16))
                        - limbs[2].clone() * Expression::Constant(F::from(1 << 32))
                        - limbs[3].clone() * Expression::Constant(F::from(1 << 48))),
            ]
        });

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
            Self::range_check_for_limb(meta, &limb, &q_decompose, &t_range16);
        }

        // Rotation
        let q_rot63 = meta.complex_selector();
        let _ = meta.create_gate("rotate right 63", |meta| {
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

        Blake2bConfig {
            _ph: PhantomData,
            q_decompose,
            q_add,
            full_number_u64,
            limbs,
            t_range16,
            carry,
            q_rot63,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        self.assign_addition_rows(&config, &mut layouter);

        Self::populate_lookup_table16(&config, &mut layouter)?;

        // Rotation
        self.assign_rotation_rows(&config, &mut layouter);

        Ok(())
    }
}

impl<F: Field + From<u64>> Blake2bCircuit<F> {
    fn assign_rotation_rows(&self, config: &Blake2bConfig<F>, layouter: &mut impl Layouter<F>) {
        let _ = layouter.assign_region(
            || "rotate 63",
            |mut region| {
                let _ = config.q_rot63.enable(&mut region, 0);

                let mut first_row = self.rotation_trace[0].to_vec();
                first_row.push(Value::known(F::ZERO));
                let mut second_row = self.rotation_trace[1].to_vec();
                second_row.push(Value::known(F::ZERO));
                Self::assign_row_from_values(&config, &mut region, first_row, 0);
                Self::assign_row_from_values(&config, &mut region, second_row, 1);
                Ok(())
            },
        );
    }

    fn assign_addition_rows(&self, config: &Blake2bConfig<F>, layouter: &mut impl Layouter<F>) {
        let _ = layouter.assign_region(
            || "decompose",
            |mut region| {
                let _ = config.q_add.enable(&mut region, 0);

                Self::assign_row_from_values(
                    &config,
                    &mut region,
                    self.addition_trace[0].to_vec(),
                    0,
                );
                Self::assign_row_from_values(
                    &config,
                    &mut region,
                    self.addition_trace[1].to_vec(),
                    1,
                );
                Self::assign_row_from_values(
                    &config,
                    &mut region,
                    self.addition_trace[2].to_vec(),
                    2,
                );
                Ok(())
            },
        );
    }

    fn populate_lookup_table16(config: &Blake2bConfig<F>, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "range check table",
            |mut table| {
                // assign the table
                for i in 0..1 << 16 {
                    table.assign_cell(
                        || "value",
                        config.t_range16,
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
    fn new_for_unknown_values() -> Self {
        Blake2bCircuit {
            _ph: PhantomData,
            addition_trace: [[Value::unknown(); 6]; 3],
            rotation_trace: [[Value::unknown(); 5]; 2],
        }
    }

    fn new_for_addition_alone(trace: [[Value<F>; 6]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            addition_trace: trace,
            rotation_trace: [[Value::unknown(); 5]; 2], // TODO: check this
        }
    }

    fn range_check_for_limb(
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
        config: &Blake2bConfig<F>,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) {
        let _ = config.q_decompose.enable(region, offset);
        let _ = region.assign_advice(
            || "full number",
            config.full_number_u64,
            offset.clone(),
            || row[0],
        );
        let _ = region.assign_advice(|| "limb0", config.limbs[0], offset.clone(), || row[1]);
        let _ = region.assign_advice(|| "limb1", config.limbs[1], offset.clone(), || row[2]);
        let _ = region.assign_advice(|| "limb2", config.limbs[2], offset.clone(), || row[3]);
        let _ = region.assign_advice(|| "limb3", config.limbs[3], offset.clone(), || row[4]);
        let _ = region.assign_advice(|| "carry", config.carry, offset.clone(), || row[5]);
    }
}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;
    let max_u64 = Value::known(Fr::from(((1u128 << 64) - 1) as u64));
    let max_u16 = Value::known(Fr::from((1 << 16) - 1));
    let one = Value::known(Fr::ONE);
    let zero = Value::known(Fr::ZERO);
    let trace = [
        [max_u64, max_u16, max_u16, max_u16, max_u16, zero],
        [one, one, zero, zero, zero, zero],
        [zero, zero, zero, zero, zero, one],
    ];

    let circuit = Blake2bCircuit::<Fr>::new_for_addition_alone(trace);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[cfg(test)]
mod tests;