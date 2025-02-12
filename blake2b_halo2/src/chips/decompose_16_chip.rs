use super::*;
use crate::chips::decomposition_trait::Decomposition;
use halo2_proofs::circuit::AssignedCell;

#[derive(Clone, Debug)]
pub struct Decompose16Chip<F: Field> {
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 4],
    q_decompose: Selector,
    t_range: TableColumn,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Decomposition<F, 4> for Decompose16Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 4],
    ) -> Self {
        let q_decompose = meta.complex_selector();
        let t_range = meta.lookup_table_column();

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

        for limb in limbs {
            Self::_range_check_for_limb(meta, &limb, &q_decompose, &t_range);
        }

        Self {
            full_number_u64,
            q_decompose,
            limbs,
            t_range,
            _ph: PhantomData,
        }
    }

    fn populate_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
    ) -> Option<Vec<AssignedCell<F, F>>> {
        let _ = self.q_decompose.enable(region, offset);
        let _ = region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0]);
        let limb_0 = region.assign_advice(|| "limb0", self.limbs[0], offset, || row[1]).ok()?;
        let limb_1 = region.assign_advice(|| "limb1", self.limbs[1], offset, || row[2]).ok()?;
        let limb_2 = region.assign_advice(|| "limb2", self.limbs[2], offset, || row[3]).ok()?;
        let limb_3 = region.assign_advice(|| "limb3", self.limbs[3], offset, || row[4]).ok()?;

        Some(vec![limb_0, limb_1, limb_2, limb_3])
    }

    fn populate_lookup_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let lookup_column = self.t_range;
        Self::_populate_lookup_table(layouter, lookup_column)?;

        Ok(())
    }

    fn _populate_lookup_table(
        layouter: &mut impl Layouter<F>,
        lookup_column: TableColumn,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "range 16bit check table",
            |mut table| {
                // assign the table
                for i in 0..1 << 16 {
                    table.assign_cell(
                        || "value",
                        lookup_column,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn generate_row_from_value(
        &mut self,
        region: &mut Region<F>,
        value: Value<F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let _ = self.q_decompose.enable(region, offset);
        let result = region.assign_advice(|| "full number", self.full_number_u64, offset, || value);

        let limbs: [Value<F>; 4] =
            (0..4).map(|i| Self::get_limb_from(value, i)).collect::<Vec<_>>().try_into().unwrap();

        for (i, limb) in limbs.iter().enumerate() {
            let _ = region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || *limb);
        }
        result
    }

    fn get_limb_from(value: Value<F>, limb_number: usize) -> Value<F> {
        value.and_then(|v| {
            let binding = v.to_repr();
            let a_bytes = binding.as_ref();
            Value::known(F::from(
                a_bytes[2 * limb_number] as u64 + 256u64 * a_bytes[2 * limb_number + 1] as u64,
            ))
        })
    }
}
