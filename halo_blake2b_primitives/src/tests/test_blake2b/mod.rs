mod blake2b_ciruit_short;

use super::*;
use halo2_proofs::dev::MockProver;
use crate::tests::test_blake2b::blake2b_ciruit_short::Blake2bCircuitShort;

#[test]
fn test_blake2b() {
    let output_size = value_for(64u128);
    let input = [zero();16];
    let input_size = zero();
    let circuit = Blake2bCircuitShort::new_for(output_size, input, input_size);
    let prover = MockProver::run(17, &circuit, vec![]).unwrap();
    prover.verify().unwrap();

}
