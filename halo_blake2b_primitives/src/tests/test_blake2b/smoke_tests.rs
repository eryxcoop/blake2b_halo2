use crate::tests::test_blake2b::vector_tests::run_test;
use super::*;

#[test]
fn test_blake2b_single_empty_block_positive() {
    let output_size = 64;
    let input = vec![];
    let input_size = 0;
    let expected_output_state = _correct_output_for_empty_input_64();
    let circuit = Blake2bCircuit::<Fr>::new_for(input, input_size, output_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_blake2b_single_empty_block_negative() {
    let output_size = 64;
    let input = vec![];
    let input_size = 0;
    let mut expected_output_state = _correct_output_for_empty_input_64();
    expected_output_state[7] = Fr::from(14u64); // Wrong value

    let circuit = Blake2bCircuit::<Fr>::new_for(input, input_size, output_size);
    let prover = MockProver::run(17, &circuit, vec![expected_output_state.to_vec()]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_blake2b_input_constrained() {
    let input = String::from("0001");
    let out = String::from("1c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5");
    let key = String::from("");
    run_test(&input, &key, &out);
}

fn _correct_output_for_empty_input_64() -> [Fr; 64] {
    [
        Fr::from(120),
        Fr::from(106),
        Fr::from(2),
        Fr::from(247),
        Fr::from(66),
        Fr::from(1),
        Fr::from(89),
        Fr::from(3),
        Fr::from(198),
        Fr::from(198),
        Fr::from(253),
        Fr::from(133),
        Fr::from(37),
        Fr::from(82),
        Fr::from(210),
        Fr::from(114),
        Fr::from(145),
        Fr::from(47),
        Fr::from(71),
        Fr::from(64),
        Fr::from(225),
        Fr::from(88),
        Fr::from(71),
        Fr::from(97),
        Fr::from(138),
        Fr::from(134),
        Fr::from(226),
        Fr::from(23),
        Fr::from(247),
        Fr::from(31),
        Fr::from(84),
        Fr::from(25),
        Fr::from(210),
        Fr::from(94),
        Fr::from(16),
        Fr::from(49),
        Fr::from(175),
        Fr::from(238),
        Fr::from(88),
        Fr::from(83),
        Fr::from(19),
        Fr::from(137),
        Fr::from(100),
        Fr::from(68),
        Fr::from(147),
        Fr::from(78),
        Fr::from(176),
        Fr::from(75),
        Fr::from(144),
        Fr::from(58),
        Fr::from(104),
        Fr::from(91),
        Fr::from(20),
        Fr::from(72),
        Fr::from(183),
        Fr::from(85),
        Fr::from(213),
        Fr::from(111),
        Fr::from(112),
        Fr::from(26),
        Fr::from(254),
        Fr::from(155),
        Fr::from(226),
        Fr::from(206),
    ]
}
