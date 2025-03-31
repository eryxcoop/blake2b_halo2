use super::*;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::types::{AssignedBlake2bWord, AssignedRow};

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
pub struct XorConfig {
    /// Lookup table columns
    t_xor_left: TableColumn,
    t_xor_right: TableColumn,
    t_xor_out: TableColumn,

    /// Selector for the xor gate
    pub q_xor: Selector,

    /// Decomposition
    decompose: Decompose8Config
}

impl XorConfig {
    /// Method that populates the lookup table. Must be called only once in the user circuit.
    pub fn populate_xor_lookup_table<F: PrimeField>(
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

    /// This method generates the xor rows in the trace. If the previous cell in the region is one
    /// of the operands, it won't be copied. Otherwise, it will be copied from the cell_to_copy,
    /// generating an extra row in the circuit.
    pub fn generate_xor_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        use_previous_cell: bool,
    ) -> Result<AssignedRow<F>, Error> {
        let difference_offset = if use_previous_cell { 1 } else { 0 };
        self.q_xor.enable(region, *offset - difference_offset)?;

        let result_value = previous_cell
            .value()
            .zip(cell_to_copy.value())
            .map(|(v0, v1)| auxiliar_functions::xor_words(v0, v1));

        self.decompose.generate_row_from_cell(region, cell_to_copy, *offset)?;
        *offset += 1;

        if !use_previous_cell {
            self.decompose.generate_row_from_cell(region, previous_cell, *offset)?;
            *offset += 1;
        }

        let result_row = self.decompose.generate_row_from_value_and_keep_row(
            region,
            result_value.and_then(|word| Value::known(F::from(word.0))),
            *offset,
        )?;
        *offset += 1;

        Ok(result_row)
    }

    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        limbs_8_bits: [Column<Advice>; 8],
        decompose: Decompose8Config,
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
            decompose
        }
    }

    pub fn unknown_trace<F: PrimeField>() -> [[Value<F>; 9]; 3] {
        [[Value::unknown(); 9]; 3]
    }
}
