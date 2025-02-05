use super::*;
use crate::chips::blake2b_table16_chip::Blake2bTable16Chip;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use std::array;

pub struct Blake2bMixingCircuit<F: Field> {
    _ph: PhantomData<F>,
    x: Value<F>,
    y: Value<F>,
    v_a_initial: Value<F>,
    v_b_initial: Value<F>,
    v_c_initial: Value<F>,
    v_d_initial: Value<F>,
    v_a_final: Value<F>,
    v_b_final: Value<F>,
    v_c_final: Value<F>,
    v_d_final: Value<F>,
}

#[derive(Clone)]
pub struct Blake2bMixingConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    blake2b_table16_chip: Blake2bTable16Chip<F>,
}

impl<F: PrimeField> Circuit<F> for Blake2bMixingCircuit<F> {
    type Config = Blake2bMixingConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            x: Value::unknown(),
            y: Value::unknown(),
            v_a_initial: Value::unknown(),
            v_b_initial: Value::unknown(),
            v_c_initial: Value::unknown(),
            v_d_initial: Value::unknown(),
            v_a_final: Value::unknown(),
            v_b_final: Value::unknown(),
            v_c_final: Value::unknown(),
            v_d_final: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        meta.enable_equality(full_number_u64);

        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        for limb in limbs {
            meta.enable_equality(limb);
        }

        let blake2b_table16_chip =
            Blake2bTable16Chip::configure(meta, full_number_u64, limbs);

        Self::Config {
            _ph: PhantomData,
            blake2b_table16_chip,
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.blake2b_table16_chip.initialize_with(&mut layouter);

        let a = config.blake2b_table16_chip.new_row_from_value(self.v_a_initial, &mut layouter)?;
        let b = config.blake2b_table16_chip.new_row_from_value(self.v_b_initial, &mut layouter)?;
        let c = config.blake2b_table16_chip.new_row_from_value(self.v_c_initial, &mut layouter)?;
        let d = config.blake2b_table16_chip.new_row_from_value(self.v_d_initial, &mut layouter)?;
        let x = config.blake2b_table16_chip.new_row_from_value(self.x, &mut layouter)?;
        let y = config.blake2b_table16_chip.new_row_from_value(self.y, &mut layouter)?;

        // v[a] = ((v[a] as u128 + v[b] as u128 + x as u128) % (1 << 64)) as u64;
        let a_plus_b = config.blake2b_table16_chip.add(a, b.clone(), &mut layouter);
        let a = config.blake2b_table16_chip.add(a_plus_b, x, &mut layouter);
        // Self::assert_values_are_equal(a, value_for(13481588052017302553u64));

        // v[d] = rotr_64(v[d] ^ v[a], 32);
        let d_xor_a = config.blake2b_table16_chip.xor(d, a.clone(), &mut layouter);
        let d = config.blake2b_table16_chip.rotate_right_32(d_xor_a, &mut layouter);
        // Self::assert_values_are_equal(d, value_for(955553433272085144u64));

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = config.blake2b_table16_chip.add(c, d.clone(), &mut layouter);
        // Self::assert_values_are_equal(c, value_for(8596445010228097952u64));

        // v[b] = rotr_64(v[b] ^ v[c], 24);
        let b_xor_c = config.blake2b_table16_chip.xor(b, c.clone(), &mut layouter);
        let b = config.blake2b_table16_chip.rotate_right_24(b_xor_c, &mut layouter);
        // Self::assert_values_are_equal(b, value_for(3868997964033118064u64));

        // v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
        let a_plus_b = config.blake2b_table16_chip.add(a.clone(), b.clone(), &mut layouter);
        let a = config.blake2b_table16_chip.add(a_plus_b, y, &mut layouter);
        // Self::assert_values_are_equal(a, value_for(17350586016050420617u64));

        // v[d] = rotr_64(v[d] ^ v[a], 16);
        let d_xor_a = config.blake2b_table16_chip.xor(d.clone(), a.clone(), &mut layouter);
        let d = config.blake2b_table16_chip.rotate_right_16(d_xor_a, &mut layouter);
        // Self::assert_values_are_equal(d, value_for(17370944012877629853u64));

        // v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
        let c = config.blake2b_table16_chip.add(c.clone(), d.clone(), &mut layouter);
        // Self::assert_values_are_equal(c, value_for(7520644949396176189u64));

        // v[b] = rotr_64(v[b] ^ v[c], 63);
        let b_xor_c = config.blake2b_table16_chip.xor(b.clone(), c.clone(), &mut layouter);
        let b = config.blake2b_table16_chip.rotate_right_63(b_xor_c, &mut layouter);

        // Check the result equals the expected one
        Self::assert_values_are_equal(a, self.v_a_final);
        Self::assert_values_are_equal(b, self.v_b_final);
        Self::assert_values_are_equal(c, self.v_c_final);
        Self::assert_values_are_equal(d, self.v_d_final);

        Ok(())
    }
}

impl<F: PrimeField> Blake2bMixingCircuit<F> {
    fn assert_values_are_equal(obtained_cell: AssignedCell<F, F>, expected_value: Value<F>) {
        obtained_cell.value().copied().and_then(|x| {
            expected_value.and_then(|y| {
                assert_eq!(x, y);
                Value::<F>::unknown()
            })
        });
    }

    pub fn new_for(
        x: Value<F>,
        y: Value<F>,
        v_a_initial: Value<F>,
        v_b_initial: Value<F>,
        v_c_initial: Value<F>,
        v_d_initial: Value<F>,
        v_a_final: Value<F>,
        v_b_final: Value<F>,
        v_c_final: Value<F>,
        v_d_final: Value<F>,
    ) -> Self {
        Self {
            _ph: PhantomData,
            x,
            y,
            v_a_initial,
            v_b_initial,
            v_c_initial,
            v_d_initial,
            v_a_final,
            v_b_final,
            v_c_final,
            v_d_final,
        }
    }
}
