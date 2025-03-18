use super::*;
use halo2_proofs::circuit::AssignedCell;
use crate::auxiliar_functions::{field_for, get_limb_from_field};

/// This config handles the decomposition of 64-bit numbers into 8-bit limbs in the trace
#[derive(Clone, Debug)]
pub struct Decompose8Config {
    /// The full number and the limbs are not owned by the config.
    full_number_u64: Column<Advice>,
    /// There are 8 limbs of 8 bits each
    limbs: [Column<Advice>; 8],

    /// Selector that turns on the gate that defines if the limbs should add up to the full number
    q_decompose: Selector,
    /// Table of [0, 2^8) to check if the limb is in the correct range
    t_range: TableColumn,
}

impl Decompose8Config {
    /// The full number and the limbs are not owned by the config.
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        let t_range = meta.lookup_table_column();
        let q_decompose = meta.complex_selector();

        /// Gate that checks if the decomposition is correct
        meta.create_gate("decompose in 8 bit words", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let limbs: Vec<Expression<F>> =
                limbs.iter().map(|column| meta.query_advice(*column, Rotation::cur())).collect();
            vec![
                q_decompose
                    * (full_number
                    - limbs[0].clone()
                    - limbs[1].clone() * Expression::Constant(F::from(1 << 8))
                    - limbs[2].clone() * Expression::Constant(F::from(1 << 16))
                    - limbs[3].clone() * Expression::Constant(F::from(1 << 24))
                    - limbs[4].clone() * Expression::Constant(F::from(1 << 32))
                    - limbs[5].clone() * Expression::Constant(F::from(1 << 40))
                    - limbs[6].clone() * Expression::Constant(F::from(1 << 48))
                    - limbs[7].clone() * Expression::Constant(F::from(1 << 56))),
            ]
        });

        /// Range checks for all the limbs
        /// I think its fine to explicitly add the lookup call here rather than having the function
        /// call (at the end of the day you use it only twice).
        for limb in limbs {
            Self::range_check_for_limb(meta, &limb, &q_decompose, &t_range);
        }

        Self {
            full_number_u64,
            limbs,
            q_decompose,
            t_range,
        }
    }

    // [Zhiyong comment - answered] no need to implement this method, unless we would use wrapping types
    //
    // We need this to be able to access the limbs column. We don't have access outside the chip
    pub fn assign_constant_in_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        constant: usize,
        offset: usize,
        name: &str,
        limb_index: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice_from_constant(
            || name,
            self.limbs[limb_index],
            offset,
            F::from(constant as u64),
        )
    }
}

impl Decomposition<8> for Decompose8Config {
    const LIMB_SIZE: usize = 8;
    fn range_table_column(&self) -> TableColumn {
        self.t_range
    }

    fn populate_row_from_values<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        // [Inigo comment - answered] If you know this value is going to have size 9, you should use an array here
        // row: [Value<F>; 9]
        //
        // This is because the method is implemented for the decompose 8 and the decompose 4 trait.
        // we used a vector to be able to keep the same signature for both implementations.
        // We can also use &[Value<F>]
        row: &[Value<F>],
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        self.q_decompose.enable(region, offset)?;
        let full_number =
            region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0])?;

        let limbs = (0..8)
            .map(|i| {
                region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || row[i + 1])
            })
            .collect::<Result<Vec<_>, _>>()?;

        //return the full number and the limbs
        Ok(std::iter::once(full_number).chain(limbs).collect())
    }

    fn generate_row_from_value<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let full_number_cell =
            self.generate_row_from_value_and_keep_row(region, value, offset)?[0].clone();
        Ok(full_number_cell)
    }

    fn generate_row_from_bytes<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        bytes: [Value<F>; 8],
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let mut full_number = F::ZERO;

        for byte in bytes.iter().rev() {
            byte.and_then(|v| {
                full_number *= F::from(256u64);
                full_number += v;
                Value::<F>::unknown()
            });
        }
        self.generate_row_from_value_and_keep_row(region, Value::known(full_number), offset)
    }

    fn generate_row_from_value_and_keep_row<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        self.q_decompose.enable(region, offset)?;
        let full_number_cell =
            region.assign_advice(|| "full number", self.full_number_u64, offset, || value)?;

        let mut result = vec![full_number_cell];

        let limbs: [Value<F>; 8] =
            (0..8).map(|i| Self::get_limb_from(value, i)).collect::<Vec<_>>().try_into().unwrap();

        for (i, limb) in limbs.iter().enumerate() {
            let limb_cell =
                region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || *limb)?;
            result.push(limb_cell);
        }

        Ok(result)
    }

    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F> {
        value.map(|v| field_for(get_limb_from_field(v, limb_number)))
    }
}
