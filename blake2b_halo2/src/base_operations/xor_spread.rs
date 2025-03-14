use std::array;
use halo2_proofs::circuit::AssignedCell;
use crate::auxiliar_functions::{value_for, field_for};
use crate::base_operations::decompose_8::Decompose8Config;
use crate::base_operations::xor::Xor;
use super::*;

#[derive(Clone, Debug)]
pub struct XorSpreadConfig {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
    extra: Column<Advice>,

    t_range: TableColumn, // TODO: unify with Decompose8Config
    t_spread: TableColumn,

    q_xor: Selector,
}

impl Xor for XorSpreadConfig {
    /// Method that populates the spread lookup tables. Must be called only once in the user circuit.
    fn populate_xor_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.populate_spread_table(layouter)?;
        Ok(())
    }

    fn generate_xor_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        decompose_8_config: &Decompose8Config,
        use_previous_cell: bool,
    ) -> Result<[AssignedCell<F, F>; 9], Error> {
        let value_lhs = previous_cell.value().copied();
        let value_rhs = cell_to_copy.value().copied();

        if !use_previous_cell {
            decompose_8_config.generate_row_from_cell(region, previous_cell, *offset)?;
            *offset += 1;
        }

        decompose_8_config.generate_row_from_cell(region, cell_to_copy, *offset)?;
        *offset += 1;

        // [Inigo comment - answered] It is a bit unclear what is going on here. How do you guarantee that the value being
        // assigned here is the same as the input?
        // Maybe soundness issue? copy constraint missing
        //
        // The gate is guaranteeing soundness here
        self.populate_spread_limbs_of(region, offset, value_lhs);
        *offset += 1;

        self.populate_spread_limbs_of(region, offset, value_rhs);
        *offset += 1;

        let value_result = value_lhs.zip(value_rhs).map(|(v0, v1)| {
            auxiliar_functions::xor_field_elements(v0, v1)
        });

        self.populate_spread_limbs_of(region, offset, value_result);
        *offset += 1;

        let result_row = decompose_8_config.generate_row_from_value_and_keep_row(
            region,
            value_result,
            *offset,
        )?;

        self.q_xor.enable(region, *offset)?;
        *offset += 1;

        value_lhs.zip(value_rhs).zip(value_result).map(|((lhs, rhs), result)| {
            let lhs_limb_values = auxiliar_functions::decompose_field_8bit_limbs(lhs);
            let rhs_limb_values = auxiliar_functions::decompose_field_8bit_limbs(rhs);
            let result_limb_values = auxiliar_functions::decompose_field_8bit_limbs(result);

            let empty_spread_positions = Self::empty_spread_positions::<F>();
            let columns_in_order =
                Self::columns_in_order::<F>(self.full_number_u64, self.limbs, self.extra);
            for i in 0..8 {
                let z_i = (Self::spread_bits::<F>(lhs_limb_values[i])
                    + Self::spread_bits::<F>(rhs_limb_values[i])
                    - Self::spread_bits::<F>(result_limb_values[i]))
                    / 2;

                region
                    .assign_advice(
                        || format!("reminder z_{}", i),
                        columns_in_order[empty_spread_positions[i].1],
                        // We need to subtract 6 since we are in the offset 7 because we already assigned all rows
                        *offset + empty_spread_positions[i].0 - 6,
                        || value_for::<u16, F>(z_i),
                    )
                    .unwrap();
            }

            Value::<F>::unknown()
        });

        Ok(result_row.try_into().unwrap())
    }
}

impl XorSpreadConfig {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        limbs: [Column<Advice>; 8],
        full_number_u64: Column<Advice>,
        extra: Column<Advice>,
    ) -> Self {
        let q_xor = meta.complex_selector();
        let t_range = meta.lookup_table_column();
        let t_spread = meta.lookup_table_column();

        let columns = Self::columns_in_order::<F>(full_number_u64, limbs, extra);

        let empty_spread_positions: [(usize, usize); 8] = Self::empty_spread_positions::<F>();

        meta.create_gate("xor with spread", |meta| {
            let q_xor = meta.query_selector(q_xor);
            let mut grid: [[Expression<F>; 10]; 6] =
                array::from_fn(|_| array::from_fn(|_| Expression::Constant(F::ZERO)));
            #[allow(clippy::needless_range_loop)]
            for row in 0..6 {
                for col in 0..10 {
                    grid[row][col] = meta.query_advice(columns[col], Rotation(row as i32 - 5));
                }
            }
            let z_expr = empty_spread_positions
                .iter()
                .map(|&(row, col)| &grid[row][col])
                .collect::<Vec<_>>();

            let mut gates = vec![];
            for i in 0..8 {
                gates.push(
                    q_xor.clone()
                        * (grid[2][i + 1].clone() + grid[3][i + 1].clone()
                            - grid[4][i + 1].clone()
                            - Expression::Constant(field_for(2u16)) * z_expr[i].clone()),
                );
            }

            gates
        });

        // Lookup spread lhs
        Self::lookup_spread_rows(meta, q_xor, t_range, t_spread, columns, -5, -3);

        // Lookup spread rhs
        Self::lookup_spread_rows(meta, q_xor, t_range, t_spread, columns, -4, -2);

        // Lookup spread result
        Self::lookup_spread_rows(meta, q_xor, t_range, t_spread, columns, 0, -1);

        // Lookup empty spread
        for (row, column_index) in empty_spread_positions.iter() {
            meta.lookup("reminder spread", |meta| {
                let q_xor = meta.query_selector(q_xor);
                let empty_spread_limb =
                    meta.query_advice(columns[*column_index], Rotation(*row as i32 - 5));

                vec![(q_xor.clone() * empty_spread_limb, t_spread)]
            });
        }

        Self {
            full_number_u64,
            limbs,
            extra,
            t_range,
            t_spread,
            q_xor,
        }
    }

    fn populate_spread_limbs_of<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        value: Value<F>,
    ) {
        value.and_then(|lhs| {
            let lhs_limb_values = auxiliar_functions::decompose_field_8bit_limbs(lhs);
            for (i, limb) in lhs_limb_values.iter().enumerate() {
                region
                    .assign_advice(
                        || "lhs limb",
                        self.limbs[i],
                        *offset,
                        || value_for::<u16, F>(Self::spread_bits::<F>(*limb)),
                    )
                    .unwrap();
            }
            Value::<F>::unknown()
        });
    }

    fn lookup_spread_rows<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        q_xor: Selector,
        t_range: TableColumn,
        t_spread: TableColumn,
        columns: [Column<Advice>; 10],
        original_rotation: i32,
        spread_rotation: i32,
    ) {
        #[allow(clippy::needless_range_loop)]
        for i in 1..9 {
            meta.lookup("spread", |meta| {
                let q_xor = meta.query_selector(q_xor);
                let original_limb = meta.query_advice(columns[i], Rotation(original_rotation));
                let spread_limb = meta.query_advice(columns[i], Rotation(spread_rotation));
                vec![
                    (q_xor.clone() * original_limb.clone(), t_range),
                    (q_xor.clone() * spread_limb.clone(), t_spread),
                ]
            });
        }
    }

    // [Inigo comment - answered] this is only used once - why not have it directly in the implementation of the trait?
    //
    // This is only used for the xor spread implementation, it is not a general method for the xor
    // trait.
    fn populate_spread_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "xor spread table",
            |mut table| {
                for i in 0..1 << 8 {
                    table.assign_cell(
                        || "original value",
                        self.t_range,
                        i,
                        || value_for::<u64, F>(i as u64),
                    )?;
                    table.assign_cell(
                        || "spread value",
                        self.t_spread,
                        i,
                        || value_for::<u64, F>(Self::spread_bits::<F>(i as u8) as u64),
                    )?;
                }
                Ok(())
            },
        )
    }

    fn spread_bits<F: PrimeField>(x: u8) -> u16 {
        let mut spread = 0;
        for i in 0..8 {
            spread |= ((x & (1 << i)) as u16) << i;
        }
        spread
    }

    fn empty_spread_positions<F: PrimeField>() -> [(usize, usize); 8] {
        [(2, 0), (3, 0), (4, 0), (1, 9), (2, 9), (3, 9), (4, 9), (5, 9)]
    }

    fn columns_in_order<F: PrimeField>(
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
        extra: Column<Advice>,
    ) -> [Column<Advice>; 10] {
        [
            full_number_u64,
            limbs[0],
            limbs[1],
            limbs[2],
            limbs[3],
            limbs[4],
            limbs[5],
            limbs[6],
            limbs[7],
            extra,
        ]
    }
}
