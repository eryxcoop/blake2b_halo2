use super::*;
use crate::types::{get_word_biguint_from_le_field, AssignedNative};
use crate::types::blake2b_word::{AssignedBlake2bWord, Blake2bWord};
use crate::types::byte::AssignedByte;
use crate::types::row::AssignedRow;

/// This config handles the decomposition of 64-bit numbers into 8-bit limbs in the trace,
/// where each limbs is range checked regarding the designated limb size.
/// T is the amount of limbs that the number will be decomposed into.
/// Little endian representation is used for the limbs.
/// We also expect F::Repr to be little endian in all usages of this trait.
#[derive(Clone, Debug)]
pub(crate) struct Decompose8Config {
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
    /// Creates the corresponding gates and lookups to constrain range-checks and 8-limb
    /// decomposition of 64-bit numbers.
    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        // The full number and the limbs are not owned by the config.
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

        /// Range checks for all the limbs (range [0,255])
        for limb in limbs {
            Self::range_check_for_limb(meta, &limb, &q_range, &t_range);
        }

        Self {
            full_number_u64,
            limbs,
            q_decompose,
            t_range,
            q_range,
        }
    }

    /// Creates the lookup of an 8-bit limb. It uses the [t-range] table, which is filled in the
    /// [self.populate_lookup_table()] method, and the [q_range], which is turned on whenever needed
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

    /// Given an array of [AssignedNative] byte-values, it puts in the circuit a full row with those
    /// bytes in the limbs and the resulting full number in the first column. By turning on the
    /// q_decompose and q_range selectors, we ensure that each limb is in the range [0,255] and
    /// that the decomposition of the limbs is correct in relation with the full number.
    pub(crate) fn generate_row_from_assigned_bytes<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        // [zhiyong]: &[AssignedByte<F>; 8]
        bytes: &[AssignedNative<F>; 8],
        offset: usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.q_decompose.enable(region, offset)?;
        self.q_range.enable(region, offset)?;

        /// Compute the full number from the limbs
        let full_number_cell = AssignedBlake2bWord::assign_advice_word(
            region,
            "full number",
            self.full_number_u64,
            offset,
            Self::compute_full_value_u64_from_bytes(bytes),
        )?;

        let mut limbs = vec![];

        /// Fill the row with copies of the limbs
        for (index, byte_cell) in bytes.iter().enumerate() {
            let assigned_byte = AssignedByte::copy_advice_byte_from_native(  // Nice!
                region,
                "Copied input byte",
                self.limbs[index],
                offset,
                byte_cell.clone(),
            )?;
            limbs.push(assigned_byte)
        }

        Ok(AssignedRow::new(full_number_cell, limbs.try_into().unwrap()))
    }

    /// Given a list of limb values, it returns the full number value that the limbs build up to.
    fn compute_full_value_u64_from_bytes<F: PrimeField>(
        bytes: &[AssignedNative<F>; 8], // [zhiyong]: use the type AssignedByte<F>
    ) -> Value<F> {
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

    /// Fills the [t_range] table with values in the range [0,255]
    pub(crate) fn populate_lookup_table<F: PrimeField>(
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

    /// Method for generating a row from a value and keeping the full row.
    /// Given a Value, we might want to use it as an operand in the circuit, and sometimes we need
    /// to establish constraints over the result's limbs. That's why we need a way to retrieve the
    /// full row that was created from that value.
    pub(crate) fn generate_row_from_value_and_keep_row<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.q_decompose.enable(region, offset)?;
        self.q_range.enable(region, offset)?;
        let full_number_cell = AssignedBlake2bWord::assign_advice_word(
            region,
            "full number",
            self.full_number_u64,
            offset,
            value,
        )?;

        let limbs: [Value<F>; 8] =
            (0..8).map(|i| Self::get_limb_from(value, i)).collect::<Vec<_>>().try_into().unwrap();

        let assigned_limbs: Vec<AssignedByte<F>> = limbs
            .iter()
            .enumerate()
            .map(|(i, limb)| {
                AssignedByte::assign_advice_byte(
                    region,
                    "limb",
                    self.limbs[i],
                    offset,
                    limb.clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        Ok(AssignedRow::new(full_number_cell, assigned_limbs.try_into().unwrap()))
    }

    /// Given a value and a limb index, it returns the value of the limb
    fn get_limb_from<F: PrimeField>(value: Value<F>, limb_number: usize) -> Value<F> {
        value.map(|v| {
            let number = Self::get_word_limb_from_le_field(v, limb_number);
            F::from_u128(number.into())
        })
    }

    /// Given a value of 64 bits, it generates a row with the assigned cells for the full number
    /// and the limbs, and returns the full number
    pub(crate) fn generate_row_from_word_value<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        value: Value<Blake2bWord>,
        offset: usize,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let new_row =
            self.generate_row_from_value_and_keep_row(region, value.map(|v| F::from(v.0)), offset)?;
        let full_number_cell = new_row.full_number;
        Ok(full_number_cell)
    }

    /// Given a cell with a 64-bit value, it creates a new row with the copied full number and the
    /// decomposition in 8-bit limbs.
    pub(crate) fn generate_row_from_cell<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        cell: &AssignedBlake2bWord<F>,
        offset: usize,
    ) -> Result<(), Error> {
        let value = cell.value();
        let new_cells =
            self.generate_row_from_value_and_keep_row(region, value.map(|v| F::from(v.0)), offset)?;
        region.constrain_equal(cell.cell(), new_cells.full_number.cell())
    }

    /// Given a field element and a limb index in little endian form, this function checks that the
    /// field element is in range [0, 2^64-1]. If it's not, it will fail.
    /// We assume that the internal representation of the field is in little endian form. If it's
    /// not, the result is undefined and probably incorrect.
    /// Finally, it obtains the corresponding limb value in little endian. This method ensures that
    /// the limb to be a value in range [0,7].
    fn get_word_limb_from_le_field<F: PrimeField>(field: F, limb_number: usize) -> u8 {
        let big_uint_field = get_word_biguint_from_le_field(field);
        if limb_number >= 8 {
            panic!("Arguments to the function are incorrect")
        } else {
            let mut bytes = big_uint_field.to_bytes_le();
            bytes.resize(8, 0u8);
            bytes[limb_number] // Access the limb in little-endian
        }
    }
}
