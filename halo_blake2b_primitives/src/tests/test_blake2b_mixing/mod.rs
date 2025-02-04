mod blake2b_circuit_mixing;

use super::*;
use crate::tests::test_blake2b_mixing::blake2b_circuit_mixing::Blake2bMixingCircuit;
use halo2_proofs::dev::MockProver;

#[test]
fn test_b2b_g_positive() {
    let x = zero();
    let y = zero();

    // these are the values 0, 4,8, and 12 of v
    let v_a_initial = value_for(7640891576939301192u128);
    let v_b_initial = value_for(5840696475078001361u128);
    let v_c_initial = value_for(7640891576956012808u128);
    let v_d_initial = value_for(5840696475078001361u128);

    let v_a_final = value_for(17350586016050420617u128);
    let v_b_final = value_for(13537687662323754138u128);
    let v_c_final = value_for(7520644949396176189u128);
    let v_d_final = value_for(17370944012877629853u128);

    let circuit = Blake2bMixingCircuit::new_for(
        x,
        y,
        v_a_initial,
        v_b_initial,
        v_c_initial,
        v_d_initial,
        v_a_final,
        v_b_final,
        v_c_final,
        v_d_final,
    );
    let prover = MockProver::run(17, &circuit, vec![vec![Fr::from(0u64)]]).unwrap();
    prover.verify().unwrap();
}

// TODO fix test
// #[test]
// #[should_panic]
// fn test_b2b_g_negative() {
//     let x = zero();
//     let y = one(); // Wrong value for example
//
//     // these are the values 0, 4,8, and 12 of v
//     let v_a_initial = value_for(7640891576939301192u128);
//     let v_b_initial = value_for(5840696475078001361u128);
//     let v_c_initial = value_for(7640891576956012808u128);
//     let v_d_initial = value_for(5840696475078001361u128);
//
//     let v_a_final = value_for(17350586016050420617u128);
//     let v_b_final = value_for(13537687662323754138u128);
//     let v_c_final = value_for(7520644949396176189u128);
//     let v_d_final = value_for(17370944012877629853u128);
//
//     let circuit = Blake2bMixingCircuit::new_for(x, y,
//                                                 v_a_initial, v_b_initial, v_c_initial, v_d_initial,
//                                                 v_a_final, v_b_final, v_c_final, v_d_final);
//     let prover = MockProver::run(17, &circuit, vec![]).unwrap();
//     prover.verify().unwrap();
// }
