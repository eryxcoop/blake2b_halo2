use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{self, Circuit, ConstraintSystem},
};

use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Advice, Column, Expression, Selector, TableColumn};
use halo2_proofs::poly::Rotation;

struct Blake2bCircuit<F: Field> {
    _ph: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct Blake2bConfig<F: Field + Clone> {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 4],
    carry: Column<Advice>,
    q_decompose: Selector,
    q_add: Selector,
    t_range16: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Circuit<F> for Blake2bCircuit<F> {
    type Config = Blake2bConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Blake2bCircuit { _ph: PhantomData }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_decompose = meta.complex_selector();
        let q_add = meta.complex_selector();

        let full_number_u64 = meta.advice_column();
        let limbs = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
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

        meta.lookup("range_check", |meta| {
            let limbs: Vec<Expression<F>> = limbs
                .iter()
                .map(|column| meta.query_advice(*column, Rotation::cur()))
                .collect();
            let q_decompose = meta.query_selector(q_decompose);
            vec![
                (q_decompose.clone() * limbs[0].clone(), t_range16),
                (q_decompose.clone() * limbs[1].clone(), t_range16),
                (q_decompose.clone() * limbs[2].clone(), t_range16),
                (q_decompose.clone() * limbs[3].clone(), t_range16),
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
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        let value = F::from(((1u128 << 64) - 1) as u64);
        let value_1 = F::from((1 << 16) - 1);
        layouter.assign_region(
            || "decompose",
            |mut region| {
                config.q_decompose.enable(&mut region, 0)?;
                region.assign_advice(|| "full number", config.full_number_u64, 0, || Value::known(value.clone()))?;
                region.assign_advice(|| "limb0", config.limbs[0], 0, || Value::known(value_1.clone()))?;
                region.assign_advice(|| "limb1", config.limbs[1], 0, || Value::known(value_1.clone()))?;
                region.assign_advice(|| "limb2", config.limbs[2], 0, || Value::known(value_1.clone()))?;
                region.assign_advice(|| "limb3", config.limbs[3], 0, || Value::known(value_1.clone()))?;
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "range check table",
            |mut table| {
                // assign the table
                for i in 0..1 << 16
                {
                    table.assign_cell(
                        || "value",
                        config.t_range16,
                        i.clone(),
                        || Value::known(F::from(i.clone() as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;
    let circuit = Blake2bCircuit::<Fr> { _ph: PhantomData };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
