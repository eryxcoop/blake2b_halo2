use std::array;
use halo2_proofs::circuit::AssignedCell;
use crate::auxiliar_functions::{generate_row_8bits, value_for};
use crate::chips::decompose_8_chip::Decompose8Chip;
use crate::chips::xor_chip::XorChip;
use super::*;

#[derive(Clone, Debug)]
struct XorChipSpread<F: PrimeField> {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
    extra: Column<Advice>,

    t_range: TableColumn, // TODO: unify with Decompose8Chip
    t_spread: TableColumn,
    t_empty_spread: TableColumn,

    q_xor: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> XorChipSpread<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>,
                     limbs: [Column<Advice>; 8],
                     full_number_u64: Column<Advice>,
                     extra: Column<Advice>) -> Self {
        let q_xor = meta.complex_selector();
        let t_range = meta.lookup_table_column();
        let t_spread = meta.lookup_table_column();
        let t_empty_spread = meta.lookup_table_column();

        let columns = [full_number_u64, limbs[0], limbs[1],
            limbs[2], limbs[3], limbs[4], limbs[5], limbs[6],
            limbs[7], extra];

        let empty_spread_positions: [(usize, usize); 8] = [(2, 0), (3, 0), (4, 0), (1, 9), (2, 9), (3, 9), (4, 9), (5, 9)];

        meta.create_gate("xor with spread", |meta| {
            let q_xor = meta.query_selector(q_xor);
            let mut grid: [[Expression<F>; 10]; 6] = array::from_fn(|_|array::from_fn(|_|Expression::Constant(F::ZERO)));
            for row in 0..6 {
                for col in 0..10 {
                    grid[row][col] = meta.query_advice(columns[col], Rotation(row as i32 - 5));
                }
            }
            let z_expr = empty_spread_positions.iter().map(|&(row, col)| {
                &grid[row as usize][col as usize]
            }).collect::<Vec<_>>();

            vec![
                q_xor.clone() * (grid[2][1].clone() + grid[3][1].clone() - grid[4][1].clone() - z_expr[0].clone()),
                q_xor.clone() * (grid[2][2].clone() + grid[3][2].clone() - grid[4][2].clone() - z_expr[1].clone()),
                q_xor.clone() * (grid[2][3].clone() + grid[3][3].clone() - grid[4][3].clone() - z_expr[2].clone()),
                q_xor.clone() * (grid[2][4].clone() + grid[3][4].clone() - grid[4][4].clone() - z_expr[3].clone()),
                q_xor.clone() * (grid[2][5].clone() + grid[3][5].clone() - grid[4][5].clone() - z_expr[4].clone()),
                q_xor.clone() * (grid[2][6].clone() + grid[3][6].clone() - grid[4][6].clone() - z_expr[5].clone()),
                q_xor.clone() * (grid[2][7].clone() + grid[3][7].clone() - grid[4][7].clone() - z_expr[6].clone()),
                q_xor.clone() * (grid[2][8].clone() + grid[3][8].clone() - grid[4][8].clone() - z_expr[7].clone()),
            ]
        });

        // Lookup spread lhs
        Self::_lookup_spread_rows(meta, q_xor, t_range, t_spread, columns, -5, -3);

        // Lookup spread rhs
        Self::_lookup_spread_rows(meta, q_xor, t_range, t_spread, columns, -4, -2);

        // Lookup spread result
        Self::_lookup_spread_rows(meta, q_xor, t_range, t_spread, columns, 0, -1);

        // Lookup empty spread
        for (row, column_index) in empty_spread_positions.iter() {
            meta.lookup("spread", |meta| {
                let q_xor = meta.query_selector(q_xor);
                let empty_spread_limb = meta.query_advice(
                    columns[*column_index], Rotation(*row as i32 - 5)
                );

                vec![
                    (q_xor.clone() * empty_spread_limb, t_empty_spread),
                ]
            });
        }

        Self {
            full_number_u64,
            limbs,
            extra,
            t_range,
            t_spread,
            t_empty_spread,
            q_xor,
            _ph: PhantomData,
        }
    }

    /// Method that populates the spread lookup tables. Must be called only once in the user circuit.
    pub fn populate_xor_lookup_table(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self._populate_spread_table(layouter)?;
        self._populate_empty_spread_table(layouter)?;
        Ok(())
    }

    pub fn generate_xor_rows_from_cells_optimized(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: AssignedCell<F, F>,
        cell_to_copy: AssignedCell<F, F>,
        decompose_8_chip: &mut Decompose8Chip<F>,
        use_previous_cell: bool,
    ) -> Result<[AssignedCell<F, F>; 9], Error> {
        let value_lhs = previous_cell.value().copied();
        let value_rhs = cell_to_copy.value().copied();

        let difference_offset = if use_previous_cell { 1 } else { 0 };
        let last_row_offset = (*offset).clone() + difference_offset + 5;
        let _ = self.q_xor.enable(region, last_row_offset);

        let value_result = value_lhs.and_then(|v0| {
            value_rhs
                .and_then(|v1| Value::known(auxiliar_functions::xor_field_elements(v0, v1)))
        });

        if !use_previous_cell {
            decompose_8_chip.generate_row_from_cell(region, previous_cell.clone(), *offset)?;
            *offset += 1;
        }

        decompose_8_chip.generate_row_from_cell(region, cell_to_copy.clone(), *offset)?;
        *offset += 1;

        let result_row = decompose_8_chip
            .generate_row_from_value_and_keep_row(region, value_result, last_row_offset)?;
        *offset += 1;

        // Lhs
        value_lhs.and_then(|lhs| {
            let lhs_row_values = generate_row_8bits(lhs);

            Value::unknown()
        })?;

        result_row.try_into().unwrap()
    }

    fn _lookup_spread_rows(meta: &mut ConstraintSystem<F>, q_xor: Selector, t_range: TableColumn,
                           t_spread: TableColumn, columns: [Column<Advice>; 10], original_rotation: i32,
                           spread_rotation: i32) {
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

    fn _populate_spread_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "xor spread table",
            |mut table| {
                for i in 0..1 << 8 {
                    table.assign_cell(
                        || "original value",
                        self.t_range,
                        i,
                        || value_for::<u64,F>(i as u64),
                    )?;
                    table.assign_cell(
                        || "spread value",
                        self.t_spread,
                        i,
                        || value_for::<u64,F>(Self::_spread_bits_left(i as u8) as u64),
                    )?;
                }
                Ok(())
            }
        )
    }

    fn _populate_empty_spread_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "xor empty spread table",
            |mut table| {
                for i in 0..1 << 8 {
                    table.assign_cell(
                        || "spread value",
                        self.t_spread,
                        i as usize,
                        || value_for::<u64,F>(Self::_spread_bits_right(i as u8) as u64),
                    )?;
                }
                Ok(())
            }
        )
    }

    fn _spread_bits_right(mut x: u8) -> u16 {
        let mut spread = 0;
        for i in 0..8 {
            spread |= ((x & (1 << i)) as u16) << (i+1);
        }
        spread
    }

    fn _spread_bits_left(mut x: u8) -> u16 {
        let mut spread = 0;
        for i in 0..8 {
            spread |= ((x & (1 << i)) as u16) << i;
        }
        spread
    }
}
