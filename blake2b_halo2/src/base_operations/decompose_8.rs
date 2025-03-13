use super::*;
use halo2_proofs::circuit::AssignedCell;

/// This config handles the decomposition of 64-bit numbers into 8-bit limbs in the trace
// [Inigo comment - solved] Configs do not need to be parametrised by the PrimeField.
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

impl Decomposition<8> for Decompose8Config {
    const LIMB_SIZE: usize = 8;
    fn range_table_column(&self) -> TableColumn {
        self.t_range
    }

    /// The full number and the limbs are not owned by the config.
    fn configure<F: PrimeField>(
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

    /// Given an explicit vector of values, it assigns the full number and the limbs in a row of the trace
    // If you are assuming a structure in the input `row`, you should specify it in the
    // docs of the function (e.g. row[0] is a u64 value, and the rest is its decomposition).
    fn populate_row_from_values<F: PrimeField>(
        &mut self,
        region: &mut Region<F>,
        // If you know this value is going to have size 9, you should use an array here
        // row: [Value<F>; 9]
        row: Vec<Value<F>>,
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

    /// Given a value of 64 bits, it returns a row with the assigned cells for the full number and the limbs
    fn generate_row_from_value<F: PrimeField>(
        &mut self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let full_number_cell =
            self.generate_row_from_value_and_keep_row(region, value, offset)?[0].clone();
        Ok(full_number_cell)
    }

    /// Given 8 8-bit limbs, it returns a row with the assigned cells for the full number and the limbs
    fn generate_row_from_bytes<F: PrimeField>(
        &mut self,
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

    /// Given a cell with a 64-bit value, it returns a new row with the copied full number and the
    /// decomposition in 8-bit limbs
    fn generate_row_from_cell<F: PrimeField>(
        &mut self,
        region: &mut Region<F>,
        cell: &AssignedCell<F, F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = cell.value().copied();
        let new_cells = self.generate_row_from_value_and_keep_row(region, value, offset)?;
        // This seems very dangerous, and food for bugs. `generate_row_from_value_and_keep_row`
        // should be properly document (I think I made this comment somewhere else in the code base)
        region.constrain_equal(cell.cell(), new_cells[0].cell())?;
        Ok(new_cells)
    }

    /// Convenience method for generating a row from a value and keeping the full row.
    /// Given a Value, we might want to use it as an operand in the circuit, and sometimes we need
    /// to establish constraints over the result's limbs. That's why we need a way to retrieve the
    /// full row that was created from that value. An example of this could be the Generic Limb
    /// Rotation Operation, where we need to establish copy constraints over the rotated limbs.
    fn generate_row_from_value_and_keep_row<F: PrimeField>(
        // why is this mutable?
        &mut self,
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

    /// Given a value and a limb index, it returns the value of the limb
    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F> {
        value.and_then(|v| auxiliar_functions::get_value_limb_from_field(v, limb_number))
    }
}
