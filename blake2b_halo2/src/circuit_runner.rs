use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Circuit;
use crate::circuits::blake2b_circuit::Blake2bCircuit;
use super::*;


pub struct CircuitRunner;
impl CircuitRunner {
    pub fn mocked_preprocess_inputs_sintesize_prove_and_verify(input: &String, key: &String, expected: &String) {
        let (input_values,
            input_size,
            key_values,
            key_size,
            expected_output_fields,
            output_size) = Self::prepare_parameters_for_test(input, key, expected);

        let circuit = Self::create_circuit_for_inputs(input_values, input_size, key_values, key_size, output_size);
        let prover = Self::mock_prove_with_public_inputs(expected_output_fields, circuit);
        Self::verify_mock_prover(prover);
    }

    pub fn verify_mock_prover(prover: MockProver<Fr>) {
        prover.verify().unwrap()
    }

    pub fn mock_prove_with_public_inputs(expected_output_fields: [Fr; 64], circuit: impl Circuit<Fr>) -> MockProver<Fr> {
        MockProver::run(17, &circuit, vec![expected_output_fields.to_vec()]).unwrap()
    }

    pub fn create_circuit_for_inputs(input_values: Vec<Value<Fr>>, input_size: usize, key_values: Vec<Value<Fr>>, key_size: usize, output_size: usize) -> impl Circuit<Fr> {
        Blake2bCircuit::<Fr>::new_for(input_values, input_size, key_values, key_size, output_size)
    }

    pub fn prepare_parameters_for_test(input: &String, key: &String, expected: &String) -> (Vec<Value<Fr>>, usize, Vec<Value<Fr>>, usize, [Fr; 64], usize) {
        // INPUT
        let input_size = input.len() / 2; // Amount of bytes
        let input_bytes = hex::decode(input).expect("Invalid hex string");
        let input_values =
            input_bytes.iter().map(|x| Value::known(Fr::from(*x as u64))).collect::<Vec<_>>();

        // OUTPUT
        let (expected_output, output_size) = Self::formed_output_block_for(expected);
        let expected_output_fields: [Fr; 64] =
            expected_output.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<_>>().try_into().unwrap();

        // KEY
        let key_size = key.len() / 2; // Amount of bytes
        let key_bytes = hex::decode(key).expect("Invalid hex string");
        let key_values =
            key_bytes.iter().map(|x| Value::known(Fr::from(*x as u64))).collect::<Vec<_>>();

        (input_values, input_size, key_values, key_size, expected_output_fields, output_size)
    }

    pub fn formed_output_block_for(output: &String) -> ([u8; 64], usize) {
        let output_block_size = output.len() / 2; // Amount of bytes
        let output_bytes = hex::decode(output).expect("Invalid hex string");
        (output_bytes.try_into().unwrap(), output_block_size)
    }
}

