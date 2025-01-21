use crate::auxiliar_functions::*;
use crate::tests::{max_u16, max_u64, one, zero};
use crate::Blake2bCircuit;
use halo2_proofs::halo2curves::bn256::Fr;

use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem},
};

use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::sum_8bits_chip::Sum8BitsChip;
use ff::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

struct Sum8BitsTestCircuit<F: Field> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 10]; 3],
}

#[derive(Clone, Debug)]
struct Sum8BitsTestConfig<F: Field + Clone> {
    // full_number_u64: Column<Advice>,
    //
    // limbs: [Column<Advice>; 8],
    // carry: Column<Advice>,
    // t_range8: TableColumn,
    sum_8bits_chip: Sum8BitsChip<F>,
    decompose_8_chip: Decompose8Chip<F>,

    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Circuit<F> for Sum8BitsTestCircuit<F> {
    type Config = Sum8BitsTestConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: [[Value::unknown(); 10]; 3],
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for limb in limbs {
            meta.enable_equality(limb);
        }
        let t_range8 = meta.lookup_table_column();
        let carry = meta.advice_column();

        let decompose_8_chip = Decompose8Chip::configure(meta, full_number_u64, limbs, t_range8);

        let sum_8bits_chip = Sum8BitsChip::configure(
            meta,
            // limbs,
            decompose_8_chip.clone(),
            full_number_u64,
            carry,
        );

        Sum8BitsTestConfig {
            _ph: PhantomData,
            decompose_8_chip,
            sum_8bits_chip,
            // full_number_u64,
            // limbs,
            // carry,
            // t_range8,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .sum_8bits_chip
            .assign_addition_rows(&mut layouter, self.trace);
        config
            .decompose_8_chip
            .populate_lookup_table8(&mut layouter)?;
        Ok(())
    }
}

#[test]
fn test_positive_addition() {
    let trace = [
        generate_row_8bits::<Fr>(1),
        generate_row_8bits::<Fr>(1),
        generate_row_8bits::<Fr>(2),

    ];

    let circuit = Sum8BitsTestCircuit::<Fr> {
        _ph: PhantomData,
        trace: trace,
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_addition() {
    let trace = [
        generate_row_8bits::<Fr>(1),
        generate_row_8bits::<Fr>(1),
        generate_row_8bits::<Fr>(3),

    ];

    let circuit = Sum8BitsTestCircuit::<Fr> {
        _ph: PhantomData,
        trace: trace,
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

