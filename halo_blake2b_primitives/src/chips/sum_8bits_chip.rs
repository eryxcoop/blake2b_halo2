use auxiliar_functions::field_for;
use crate::chips::decompose_8_chip::Decompose8Chip;
use super::*;

#[derive(Clone, Debug)]
pub struct Sum8BitsChip<F: Field> {
    carry: Column<Advice>,
    q_add: Selector,
    _ph: PhantomData<F>,
}

impl<F: Field + From<u64>> Sum8BitsChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        decompose_8_chip: Decompose8Chip<F>,
        full_number_u64: Column<Advice>,
        carry: Column<Advice>,
    ) -> Self {
        let q_add = meta.complex_selector();

        meta.create_gate("sum mod 2 ^ 64 in 8 bits", |meta| {
            let q_add = meta.query_selector(q_add);
            let full_number_x = meta.query_advice(full_number_u64, Rotation(0));
            let full_number_y = meta.query_advice(full_number_u64, Rotation(1));
            let full_number_result = meta.query_advice(full_number_u64, Rotation(2));

            let carry = meta.query_advice(carry, Rotation(2));

            vec![
                q_add
                    * (full_number_result - full_number_x - full_number_y
                        + carry * (Expression::Constant(field_for(1u128 << 64)))),
            ]
        });

        Self {
            carry,
            q_add,
            _ph: PhantomData,
        }
    }

    pub fn assign_addition_rows(
        &mut self,
        layouter: &mut impl Layouter<F>,
        addition_trace: [[Value<F>; 10]; 3],
        decompose_8_chip: &mut Decompose8Chip<F>
    ) {
        let _ = layouter.assign_region(
            || "decompose",
            |mut region| {
                let _ = self.q_add.enable(&mut region, 0);

                self.assign_row_from_values(&mut region, addition_trace[0].to_vec(), 0, decompose_8_chip);
                self.assign_row_from_values(&mut region, addition_trace[1].to_vec(), 1, decompose_8_chip);
                self.assign_row_from_values(&mut region, addition_trace[2].to_vec(), 2, decompose_8_chip);
                Ok(())
            },
        );
    }

    fn assign_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
        decompose_8_chip: &mut Decompose8Chip<F>
    ) {
        decompose_8_chip.assign_8bit_row_from_values(region, row.clone(), offset);
        let _ = region.assign_advice(|| "carry", self.carry, offset, || row[9]);
    }
}
