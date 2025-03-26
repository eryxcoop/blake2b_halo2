use super::*;
use crate::auxiliar_functions::{field_for, get_limb_from_field};
use crate::types::{AssignedBlake2bWord, AssignedByte, AssignedElement, AssignedNative, AssignedRow, Blake2bWord};

/// This config handles the decomposition of 64-bit numbers into 8-bit limbs in the trace,
/// where each limbs is range checked regarding the designated limb size.
/// T is the amount of limbs that the number will be decomposed into.
/// Little endian representation is used for the limbs.
/// We also expect F::Repr to be little endian in all usages of this trait.
#[derive(Clone, Debug)]
pub struct Decompose8Config {
    /// The full number and the limbs are not owned by the config.
    pub full_number_u64: Column<Advice>,
    /// There are 8 limbs of 8 bits each
    pub limbs: [Column<Advice>; 8],

    /// Selector that turns on the gate that defines if the limbs should add up to the full number
    pub q_decompose: Selector,

    /// Selector that turns on the gate that defines if the limbs should be range-checked
    pub q_range: Selector,

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
        let q_range = meta.complex_selector();
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
            Self::range_check_for_limb(meta, &limb, &q_range, &t_range);
        }

        Self {
            full_number_u64,
            limbs,
            q_decompose,
            t_range,
            q_range
        }
    }

    fn range_check_for_limb<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        limb: &Column<Advice>,
        q_range: &Selector,
        t_range: &TableColumn,
    ) {
        meta.lookup(format!("lookup limb {:?}", limb), |meta| {
            let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
            let q_range = meta.query_selector(*q_range);
            vec![(q_range * limb, *t_range)]
        });
    }

    pub fn generate_row_from_assigned_bytes<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        bytes: &[AssignedNative<F>; 8],
        offset: usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.q_decompose.enable(region, offset)?;
        self.q_range.enable(region, offset)?;

        /// Compute the full number from the limbs
        let full_number_cell = AssignedBlake2bWord::<F>::new(region.assign_advice(
            || "full number",
            self.full_number_u64,
            offset,
            || Self::compute_full_value_u64_from_bytes(bytes))?);

        let mut limbs = vec![];

        /// Fill the row with copies of the limbs
        for (index, byte_cell) in bytes.iter().enumerate() {
            let assigned_cell = byte_cell.copy_advice(
                || "Copied input byte", region, self.limbs[index], offset)?;
            limbs.push(AssignedByte::<F>::new(assigned_cell)
            );
        }

        Ok(AssignedRow::new(full_number_cell, limbs.try_into().unwrap()))
    }

    fn compute_full_value_u64_from_bytes<F: PrimeField>(bytes: &[AssignedNative<F>; 8]) -> Value<F> {
        let mut full_number = F::ZERO;
        // We process the limbs from the most significant to the least significant
        for byte_cell in bytes.iter().rev() {
            byte_cell.value().and_then(|v| {
                full_number *= F::from(256u64);
                full_number += *v;
                Value::<F>::unknown()
            });
        }
        Value::known(full_number)
    }

    pub fn populate_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        const LIMB_SIZE_IN_BITS: usize = 8;
        layouter.assign_table(
            || format!("range {}-bit check table", LIMB_SIZE_IN_BITS),
            |mut table| {
                for i in 0..1 << LIMB_SIZE_IN_BITS {
                    table.assign_cell(
                        || "value",
                        self.t_range,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// Convenience method for generating a row from a value and keeping the full row.
    /// Given a Value, we might want to use it as an operand in the circuit, and sometimes we need
    /// to establish constraints over the result's limbs. That's why we need a way to retrieve the
    /// full row that was created from that value. An example of this could be the Generic Limb
    /// Rotation Operation, where we need to establish copy constraints over the rotated limbs.
    pub fn generate_row_from_value_and_keep_row<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.q_decompose.enable(region, offset)?;
        self.q_range.enable(region, offset)?;
        let full_number_cell =
            region.assign_advice(|| "full number", self.full_number_u64, offset, || value)?.into();

        let limbs: [Value<F>; 8] =
            (0..8).map(|i| Self::get_limb_from(value, i)).collect::<Vec<_>>().try_into().unwrap();

        let assigned_limbs: Vec<AssignedByte<F>> = limbs.iter().enumerate().map(|(i, limb)|{
            region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || *limb).unwrap().into()
        }).collect::<Vec<_>>();

        Ok(AssignedRow::new(
            full_number_cell,
            assigned_limbs.try_into().unwrap()
        ))
    }

    /// Given a value and a limb index, it returns the value of the limb
    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F> {
        value.map(|v| field_for(get_limb_from_field(v, limb_number)))
    }

    /// Given a value of 64 bits, it generates a row with the assigned cells for the full number
    /// and the limbs, and returns the full number
    pub fn generate_row_from_value<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<Blake2bWord>,
        offset: usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        //TODO: remove cast later on
        let value = value.map(|v| F::from(v.0));

        let new_row = self.generate_row_from_value_and_keep_row(region, value, offset)?;
        let full_number_cell = new_row.full_number;
        Ok(full_number_cell)
    }

    /// Given a cell with a 64-bit value, it creates a new row with the copied full number and the
    /// decomposition in 8-bit limbs.
    pub fn generate_row_from_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        cell: &AssignedNative<F>,
        offset: usize,
    ) -> Result<(), Error> {
        let value = cell.value().copied();
        let new_cells = self.generate_row_from_value_and_keep_row(region, value, offset)?;
        region.constrain_equal(cell.cell(), new_cells.full_number.cell())
    }
}
