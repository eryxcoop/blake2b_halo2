use super::*;
use halo2_proofs::circuit::AssignedCell;

/// This chip handles the decomposition of 64-bit numbers into 8-bit limbs in the trace
#[derive(Clone, Debug)]
pub struct Decompose8Chip<F: PrimeField> {
    /// The full number and the limbs are not owned by the chip.
    full_number_u64: Column<Advice>,
    /// There are 8 limbs of 8 bits each
    limbs: [Column<Advice>; 8],

    /// Selector that turns on the gate that defines if the limbs should add up to the full number
    q_decompose: Selector,
    /// Table of [0, 2^8) to check if the limb is in the correct range
    t_range: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Decomposition<F, 8> for Decompose8Chip<F> {
    /// The full number and the limbs are not owned by the chip.
    fn configure(
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
        for limb in limbs {
            Self::_range_check_for_limb(meta, &limb, &q_decompose, &t_range);
        }

        Self {
            full_number_u64,
            limbs,
            q_decompose,
            t_range,
            _ph: PhantomData,
        }
    }

    /// Given an explicit vector of values, it assigns the full number and the limbs in a row of the trace
    fn populate_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) -> Option<Vec<AssignedCell<F, F>>> {
        let _ = self.q_decompose.enable(region, offset);
        let full_number = region
            .assign_advice(|| "full number", self.full_number_u64, offset, || row[0])
            .unwrap();

        let limbs = (0..8)
            .map(|i| {
                region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || row[i + 1])
            })
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

        //return the full number and the limbs
        Some(std::iter::once(full_number).chain(limbs).collect())
    }

    /// Populates the table for the range check
    fn populate_lookup_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let lookup_column = self.t_range;
        Self::_populate_lookup_table(layouter, lookup_column)
    }

    fn _populate_lookup_table(
        layouter: &mut impl Layouter<F>,
        lookup_column: TableColumn,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "range 8bit check table",
            |mut table| {
                // assign the table
                for i in 0..1 << 8 {
                    table.assign_cell(
                        || "value",
                        lookup_column,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// Given a value of 64 bits, it returns a row with the assigned cells for the full number and the limbs
    fn generate_row_from_value(
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
    fn generate_row_from_bytes(
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
    fn generate_row_from_cell(
        &mut self,
        region: &mut Region<F>,
        cell: &AssignedCell<F, F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = cell.value().copied();

        let new_cells = self.generate_row_from_value_and_keep_row(region, value, offset)?;
        region.constrain_equal(cell.cell(), new_cells[0].cell())?;
        Ok(new_cells)
    }

    /// Given a value and a limb index, it returns the value of the limb
    fn get_limb_from(value: Value<F>, limb_number: usize) -> Value<F> {
        value.and_then(|v| auxiliar_functions::get_value_limb_from_field(v, limb_number))
    }

    /// Convenience method for generating a row from a value and keeping the full row
    fn generate_row_from_value_and_keep_row(
        &mut self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let _ = self.q_decompose.enable(region, offset);
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
}
