mod blake2b_ciruit_short;

use super::*;
use halo2_proofs::dev::MockProver;
use crate::tests::test_blake2b::blake2b_ciruit_short::Blake2bCircuitShort;

#[test]
fn test_blake2b_single_empty_block_positive() {
    let output_size = value_for(64u128);
    let input = [zero();16];
    let input_size = zero();
    let expected_output_state = _correct_final_state_for_empty_input();
    let circuit = Blake2bCircuitShort::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_blake2b_single_empty_block_negative() {
    let output_size = value_for(64u128);
    let input = [zero();16];
    let input_size = zero();
    let mut expected_output_state = _correct_final_state_for_empty_input();
    expected_output_state[7] = Fr::from(14907649232217337814u64); // Wrong value

    let circuit = Blake2bCircuitShort::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

fn _correct_final_state_for_empty_input() -> [Fr; 8] {
    [
        Fr::from(241225442164632184u64),
        Fr::from(8273765786548291270u64),
        Fr::from(7009669069494759313u64),
        Fr::from(1825118895109998218u64),
        Fr::from(6005812539308400338u64),
        Fr::from(5453945543160269075u64),
        Fr::from(6176484666232027792u64),
        Fr::from(14907649232217337813u64)
    ]
}
