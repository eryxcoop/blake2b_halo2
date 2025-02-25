use super::*;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{
        create_proof, keygen_pk, keygen_vk_with_k, ProvingKey, VerifyingKey
    },
    poly::kzg::{
        params::ParamsKZG,
        KZGCommitmentScheme,
    },
    transcript::{CircuitTranscript, Transcript},
};



#[test]
fn test_with_real_snark() {
    let input = String::from("0001");
    let out = String::from("1c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5");
    let key = String::from("");
    let (input_values, input_size, key_values, key_size, expected_output_fields, output_size) =
        prepare_parameters_for_test(&input, &key, &out);

    let circuit: Blake2bCircuit<Fr> = Blake2bCircuit::new_for(input_values, input_size, key_values, key_size, output_size);

    let params = ParamsKZG::<Bn256>::unsafe_setup(17, &mut rand::thread_rng());
    let vk: VerifyingKey<Fr, KZGCommitmentScheme<Bn256>> = keygen_vk_with_k(&params, &circuit, 17).expect("Verifying key should be created");
    let pk: ProvingKey<Fr, KZGCommitmentScheme<Bn256>>= keygen_pk(vk.clone(), &circuit).expect("Proving key should be created");


    let mut transcript = CircuitTranscript::init();
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&expected_output_fields]],
        rand::thread_rng(),
        &mut transcript,
    ).expect("Proof generation should work");

    let proof = transcript.finalize();
    println!("{:?}\n\n Proof length: {}", proof, proof.len());
}
