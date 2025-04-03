use super::*;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::types::row::AssignedRow;
use crate::types::blake2b_word::AssignedBlake2bWord;
use crate::types::byte::Byte;

/// This config handles the xor operation in the trace. Requires a representation in 8-bit limbs
/// because it uses a lookup table like this one:
///
/// | lhs | rhs | lhs xor rhs |
/// |  0  |  0  |      0      |
/// |  0  |  1  |      1      |
/// ...
/// | 255 | 255 |      0      |
///
/// The table has 2^8 * 2^8 = 2^16 rows, since we need to check all the possible
/// combinations of 8-bit numbers.
/// Then, with the help of the Decompose8Config, the final representation in the trace will be:
///
/// | full_number_lhs    | limb_0_lhs    | limb_1_lhs    | ... | limb_7_lhs    |
/// | full_number_rhs    | limb_0_rhs    | limb_1_rhs    | ... | limb_7_rhs    |
/// | full_number_result | limb_0_result | limb_1_result | ... | limb_7_result |
#[derive(Clone, Debug)]
pub(crate) struct XorConfig {
    /// Lookup table columns
    t_xor_left: TableColumn,
    t_xor_right: TableColumn,
    t_xor_out: TableColumn,

    /// Selector for the xor gate
    pub q_xor: Selector,

    /// Decomposition
    //[zhiyong]: logically, this config should not be part of XOR
    decompose: Decompose8Config,
}

impl XorConfig {
    /// Method that populates the lookup table. Must be called only once in the user circuit.
    pub(crate) fn populate_xor_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "xor check table",
            |mut table| {
                for left in 0..256 {
                    for right in 0..256 {
                        let index = left * 256 + right;
                        let result = left ^ right;
                        table.assign_cell(
                            || "left_value",
                            self.t_xor_left,
                            index,
                            || Value::known(F::from(left as u64)),
                        )?;
                        table.assign_cell(
                            || "right_value",
                            self.t_xor_right,
                            index,
                            || Value::known(F::from(right as u64)),
                        )?;
                        table.assign_cell(
                            || "out_value",
                            self.t_xor_out,
                            index,
                            || Value::known(F::from(result as u64)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    /// This method generates the xor rows in the trace. Copying both operands into new rows on the
    /// trace and then performing the xor operation on the row limbs. Each limb of the result is
    /// looked up in a table to check that it is the xor result of the corresponding limbs of the
    /// operands
    pub(crate) fn generate_xor_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        lhs: &AssignedBlake2bWord<F>,
        rhs: &AssignedBlake2bWord<F>,
    ) -> Result<AssignedRow<F>, Error> {
        self.q_xor.enable(region, *offset)?;

        let first_operand_row = self.decompose.generate_row_from_cell(region, rhs, *offset)?;
        *offset += 1;

        let second_operand_row = self.decompose.generate_row_from_cell(region, lhs, *offset)?;
        *offset += 1;

        self.generate_xor_rows(region, offset, &first_operand_row, &second_operand_row)
    }

    /// This is similar to generate_xor_rows_from_cells but it reuses the first operand of the
    /// operation Note that this method will work only if first_operand_row is the immediate
    /// previous row in the trace.
    pub(crate) fn generate_xor_rows_reusing_first_operand<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        first_operand_row: &AssignedRow<F>,
        second_operand: &AssignedBlake2bWord<F>,
    ) -> Result<AssignedRow<F>, Error> {
        // Since the first row is being reused, the selector must be enabled for offset - 1
        self.q_xor.enable(region, *offset - 1)?;

        let second_operand_row = self.decompose.generate_row_from_cell(region, second_operand, *offset)?;
        *offset += 1;

        self.generate_xor_rows(region, offset, first_operand_row, &second_operand_row)
    }

    fn generate_xor_rows<F: PrimeField>(&self, region: &mut Region<F>, offset: &mut usize, first_operand_row: &AssignedRow<F>, second_operand_row: &AssignedRow<F>) -> Result<AssignedRow<F>, Error> {
        let mut result_limb_values: Vec<Value<Byte>> = Vec::with_capacity(8);
        for i in 0..8 {
            let left = first_operand_row.limbs[i].clone();
            let right = second_operand_row.limbs[i].clone();
            let result_value = left
                .value()
                .zip(right.value())
                .map(|(v0, v1)| v0 ^ v1);
            result_limb_values.push(result_value)
        }
        let result_value = first_operand_row.full_number
            .value()
            .zip(second_operand_row.full_number.value())
            .map(|(v0, v1)| v0 ^ v1);

        let result_row = self.decompose.create_row_with_word_and_limbs(
            region,
            result_value,
            result_limb_values.try_into().unwrap(),
            *offset,
        )?;
        *offset += 1;
        Ok(result_row)
    }

    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        limbs_8_bits: [Column<Advice>; 8],
        decompose: Decompose8Config, //[zhiyong]: is there a way to work around as decompose should not be part of xor
    ) -> Self {
        let q_xor = meta.complex_selector();
        let t_xor_left = meta.lookup_table_column();
        let t_xor_right = meta.lookup_table_column();
        let t_xor_out = meta.lookup_table_column();

        /// We need to perform a lookup for each limb, the 64-bit result will be ensured by the
        /// Decompose8Config
        for limb in limbs_8_bits {
            meta.lookup(format!("xor lookup limb {:?}", limb), |meta| {
                let left: Expression<F> = meta.query_advice(limb, Rotation(0));
                let right: Expression<F> = meta.query_advice(limb, Rotation(1));
                let out: Expression<F> = meta.query_advice(limb, Rotation(2));
                let q_xor = meta.query_selector(q_xor);
                vec![
                    (q_xor.clone() * left, t_xor_left),
                    (q_xor.clone() * right, t_xor_right),
                    (q_xor.clone() * out, t_xor_out),
                ]
            });
        }

        Self {
            t_xor_left,
            t_xor_right,
            t_xor_out,
            q_xor,
            decompose,
        }
    }
}
