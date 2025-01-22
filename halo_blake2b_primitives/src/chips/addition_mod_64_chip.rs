use crate::auxiliar_functions::field_for;
use super::*;
use crate::chips::decompose_16_chip::Decompose16Chip;

#[derive(Clone, Debug)]
pub struct AdditionMod64Chip<F: Field> {
    carry: Column<Advice>,
    q_add: Selector,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> AdditionMod64Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        decompose_16_chip: Decompose16Chip<F>,
        full_number_u64: Column<Advice>,
        carry: Column<Advice>,
    ) -> Self {
        let q_add = meta.complex_selector();

        meta.create_gate("sum mod 2 ^ 64", |meta| {
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

        decompose_16_chip.range_check_for_limbs(meta);

        Self {
            carry,
            q_add,
            _ph: PhantomData,
        }
    }

    pub fn assign_addition_rows(
        &mut self,
        layouter: &mut impl Layouter<F>,
        addition_trace: [[Value<F>; 6]; 3],
        decompose_16_chip: &mut Decompose16Chip<F>,
    ) {
        let _ = layouter.assign_region(
            || "decompose",
            |mut region| {
                let _ = self.q_add.enable(&mut region, 0);

                self.assign_row_from_values(
                    &mut region,
                    addition_trace[0].to_vec(),
                    0,
                    decompose_16_chip,
                );
                self.assign_row_from_values(
                    &mut region,
                    addition_trace[1].to_vec(),
                    1,
                    decompose_16_chip,
                );
                self.assign_row_from_values(
                    &mut region,
                    addition_trace[2].to_vec(),
                    2,
                    decompose_16_chip,
                );
                Ok(())
            },
        );
    }

    fn assign_row_from_values(
        &mut self,
        region: &mut Region<F>,
        row: Vec<Value<F>>,
        offset: usize,
        decompose_16_chip: &mut Decompose16Chip<F>,
    ) {
        decompose_16_chip.assign_16bit_row_from_values(region, row.clone(), offset);

        let _ = region.assign_advice(|| "carry", self.carry, offset, || row[5]);
    }

    pub fn unknown_trace() -> [[Value<F>; 6]; 3] {
        [[Value::unknown(); 6]; 3]
    }
}
