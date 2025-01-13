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
        let value = F::from((2 << 16) - 1);
        layouter.assign_region(
            || "decompose",
            |mut region| {
                config.q_decompose.enable(&mut region, 0)?;
                region.assign_advice(|| "full number", config.full_number_u64, 0, || Value::known(value.clone()))?;
                region.assign_advice(|| "limb0", config.limbs[0], 0, || Value::known(value.clone()))?;
                region.assign_advice(|| "limb1", config.limbs[1], 0, || Value::known(F::ONE))?;
                region.assign_advice(|| "limb2", config.limbs[2], 0, || Value::known(F::ZERO))?;
                region.assign_advice(|| "limb3", config.limbs[3], 0, || Value::known(F::ZERO))?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;
    let circuit = Blake2bCircuit::<Fr> { _ph: PhantomData };
    let prover = MockProver::run(8, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
