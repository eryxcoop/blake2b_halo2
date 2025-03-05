use crate::circuit_runner::CircuitRunner;

#[test]
fn test_with_real_snark() {
    let input = String::from("0001");
    let out = String::from("1c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5");
    let key = String::from("");

    test_in_production(input, out, key);
}

#[test]
#[should_panic]
fn test_negative_with_real_snark() {
    let input = String::from("0001");
    let out = String::from("2c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5");
    let key = String::from("");

    test_in_production(input, out, key);
}

fn test_in_production(input: String, out: String, key: String) {
    CircuitRunner::real_preprocess_inputs_sintesize_prove_and_verify(input, out, key);
}
