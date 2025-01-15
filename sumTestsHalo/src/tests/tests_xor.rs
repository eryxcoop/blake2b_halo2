use super::*;
use crate::auxiliar_functions::{spread, trash, value_for};

#[test]
fn test_positive_xor() {
    let x = max_u64();
    let y = max_u64();
    let (x_0, x_1, x_2, x_3) = ((1 << 16) - 1, (1 << 16) - 1, (1 << 16) - 1, (1 << 16) - 1);
    let (y_0, y_1, y_2, y_3) = ((1 << 16) - 1, (1 << 16) - 1, (1 << 16) - 1, (1 << 16) - 1);
    let z = zero();
    let (z_0, z_1, z_2, z_3) = (0u64, 0u64, 0u64, 0u64);

    let first_row = xor_row(x, x_0, x_1, x_2, x_3);
    let second_row = xor_row(y, y_0, y_1, y_2, y_3);;
    let last_row = xor_row(z, z_0, z_1, z_2, z_3);

    let aux_row = xor_aux_row(x_0, x_1, x_2, x_3, y_0, y_1, y_2, y_3);

    let trace: [[Value<Fr>; 9]; 4] = [
        first_row, // a
        second_row, // b
        aux_row,
        last_row, // a xor b
    ];

    let circuit = Blake2bCircuit::<Fr> {
        _ph: PhantomData,
        addition_trace: [[Value::unknown(); 6]; 3],
        rotation_trace_63: [[Value::unknown(); 5]; 2],
        rotation_trace_24: [[Value::unknown(); 5]; 3],
        xor_trace: trace,
    };
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn xor_aux_row(x_0: u64, x_1: u64, x_2: u64, x_3: u64, y_0: u64, y_1: u64, y_2: u64, y_3: u64) -> [Value<Fr>; 9] {
    // limb_i = s(a_i xor b_i) - s(a_i) - s(b_i)
    [
        trash(),
        spread_difference_value(x_0, y_0),
        spread_difference_value(x_1, y_1),
        spread_difference_value(x_2, y_2),
        spread_difference_value(x_3, y_3),
        trash(),
        trash(),
        trash(),
        trash(),
    ]
}

fn xor_row(x: Value<Fr>, x_0: u64, x_1: u64, x_2: u64, x_3: u64) -> [Value<Fr>; 9] {
    // x
    [
        x,
        value_for(x_0),
        value_for(x_1),
        value_for(x_2),
        value_for(x_3),
        value_for(spread(x_0 as u16) as u64),
        value_for(spread(x_1 as u16) as u64),
        value_for(spread(x_2 as u16) as u64),
        value_for(spread(x_3 as u16) as u64),
    ]
}

fn spread_difference_value(x_0: u64, y_0: u64) -> Value<Fr> {
    value_for((spread(x_0 as u16) + spread(y_0 as u16) - spread(x_0 as u16 ^ y_0 as u16)) as u64)
}
