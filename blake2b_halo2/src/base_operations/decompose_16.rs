use super::*;
use crate::base_operations::decomposition::Decomposition;
use crate::types::AssignedNative;

/// This config handles the decomposition of 64-bit numbers into 16-bit limbs in the trace
#[derive(Clone, Debug)]
pub struct Decompose16Config {
    /// The full number and the limbs are not owned by the config.
    full_number_u64: Column<Advice>,
    /// There are 4 limbs of 16 bits each
    limbs: [Column<Advice>; 4],

    /// Selector that turns on the gate that defines if the limbs should add up to the full number
    q_decompose: Selector,
    /// Table of [0, 2^16) to check if the limb is in the correct range
    t_range: TableColumn,
}

impl Decompose16Config {
    /// The full number and the limbs are not owned by the config.
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 4],
    ) -> Self {
        let q_decompose = meta.complex_selector();
        let t_range = meta.lookup_table_column();

        /// Gate that checks if the decomposition is correct
        meta.create_gate("decompose in 16bit words", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let full_number = meta.query_advice(full_number_u64, Rotation::cur());
            let limbs: Vec<Expression<F>> =
                limbs.iter().map(|column| meta.query_advice(*column, Rotation::cur())).collect();
            vec![
                q_decompose
                    * (full_number
                        - limbs[0].clone()
                        - limbs[1].clone() * Expression::Constant(F::from(1 << 16))
                        - limbs[2].clone() * Expression::Constant(F::from(1 << 32))
                        - limbs[3].clone() * Expression::Constant(F::from(1 << 48))),
            ]
        });

        /// Range checks for all the limbs
        for limb in limbs {
            Self::range_check_for_limb(meta, &limb, &q_decompose, &t_range);
        }

        Self {
            full_number_u64,
            q_decompose,
            limbs,
            t_range,
        }
    }
}

impl Decomposition<4> for Decompose16Config {
    const LIMB_SIZE: usize = 16;
    fn range_table_column(&self) -> TableColumn {
        self.t_range
    }

    fn populate_row_from_values<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row: &[Value<F>],
        offset: usize,
        check_decomposition: bool,
    ) -> Result<Vec<AssignedNative<F>>, Error> {
        if check_decomposition {
            self.q_decompose.enable(region, offset)?;
        }
        region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0])?;
        let limb_0 = region.assign_advice(|| "limb0", self.limbs[0], offset, || row[1])?;
        let limb_1 = region.assign_advice(|| "limb1", self.limbs[1], offset, || row[2])?;
        let limb_2 = region.assign_advice(|| "limb2", self.limbs[2], offset, || row[3])?;
        let limb_3 = region.assign_advice(|| "limb3", self.limbs[3], offset, || row[4])?;

        Ok(vec![limb_0, limb_1, limb_2, limb_3])
    }

    fn generate_row_from_value<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedNative<F>, Error> {
        let full_number_cell =
            self.generate_row_from_value_and_keep_row(region, value, offset)?[0].clone();
        Ok(full_number_cell)
    }

    fn generate_row_from_value_and_keep_row<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<Vec<AssignedNative<F>>, Error> {
        self.q_decompose.enable(region, offset)?;
        let full_number_cell =
            region.assign_advice(|| "full number", self.full_number_u64, offset, || value)?;

        let mut result = vec![full_number_cell];

        let limbs: [Value<F>; 4] =
            (0..4).map(|i| Self::get_limb_from(value, i)).collect::<Vec<_>>().try_into().unwrap();

        for (i, limb) in limbs.iter().enumerate() {
            let limb_cell =
                region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || *limb)?;
            result.push(limb_cell);
        }
        Ok(result)
    }

    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F> {
        value.map(|v| {
            let binding = v.to_repr();
            let a_bytes = binding.as_ref();
            F::from(a_bytes[2 * limb_number] as u64 + 256u64 * a_bytes[2 * limb_number + 1] as u64)
        })
    }

    fn get_full_number_u64_column(&self) -> Column<Advice> {
        self.full_number_u64.clone()
    }
}
