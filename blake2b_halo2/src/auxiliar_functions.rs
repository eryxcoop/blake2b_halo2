use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;

pub fn max_u64() -> Value<Fr> {
    value_for((1u128 << 64) - 1)
}

pub fn max_u16() -> Value<Fr> {
    let number = (1u64 << 16) - 1;
    value_for(number)
}

pub fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
pub fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}

pub fn value_for<T, F>(number: T) -> Value<F>
where
    T: Into<u128>,
    F: PrimeField,
{
    Value::known(field_for(number))
}

pub fn field_for<T, F>(number: T) -> F
where
    T: Into<u128>,
    F: PrimeField,
{
    let number: u128 = number.into();
    let lo: u64 = (number % (1u128 << 64)) as u64;
    let hi: u64 = (number / (1u128 << 64)) as u64;
    let field_pow64 = F::from(1 << 63) * F::from(2);
    F::from(hi) * field_pow64 + F::from(lo)
}

pub fn decompose_field_8bit_limbs<F: PrimeField>(number: F) -> [u8; 8] {
    (0..8).map(|i| get_limb_from_field(number, i)).collect::<Vec<_>>().try_into().unwrap()
}

pub fn generate_row_8bits<T, F>(number: T) -> [Value<F>; 10]
where
    F: PrimeField,
    T: Into<u128>,
{
    let mut number: u128 = number.into();
    let mut ans = [Value::unknown(); 10];
    ans[0] = value_for(number);
    ans[9] = value_for(0u8);
    for ans_item in ans.iter_mut().take(9).skip(1) {
        *ans_item = value_for(number % 256);
        number /= 256;
    }
    ans
}

pub fn sum_mod_64<F: PrimeField>(a: F, b: F) -> F {
    let a_value = convert_to_u64(a) as u128;
    let b_value = convert_to_u64(b) as u128;

    F::from(((a_value + b_value) % (1u128 << 64)) as u64)
}

pub fn carry_mod_64<F: PrimeField>(a: F, b: F) -> F {
    let a_value = convert_to_u64(a) as u128;
    let b_value = convert_to_u64(b) as u128;

    F::from(((a_value + b_value) / (1u128 << 64)) as u64)
}

pub fn convert_to_u64<F: PrimeField>(a: F) -> u64 {
    let binding = a.to_repr();
    let a_bytes = binding.as_ref();

    let mut a_value: u64 = 0;
    for (i, b) in a_bytes[0..8].iter().enumerate() {
        a_value += (*b as u64) * (1u64 << (8 * i));
    }
    a_value
}

pub fn xor_field_elements<F: PrimeField>(a: F, b: F) -> F {
    let a_value = convert_to_u64(a);
    let b_value = convert_to_u64(b);

    F::from(a_value ^ b_value)
}

pub fn get_value_limb_from_field<F: PrimeField>(field: F, limb_number: usize) -> Value<F> {
    value_for(get_limb_from_field(field, limb_number))
}

fn get_limb_from_field<F: PrimeField>(field: F, limb_number: usize) -> u8 {
    let binding = field.to_repr();
    let a_bytes = binding.as_ref();
    a_bytes[limb_number]
}

pub(crate) fn rotate_right_field_element<F: PrimeField>(
    value_to_rotate: F,
    rotation_degree: usize,
) -> F {
    let value_to_rotate = convert_to_u64(value_to_rotate);
    let rotation_degree = rotation_degree % 64;
    let rotated_value = ((value_to_rotate as u128) >> rotation_degree)
        | ((value_to_rotate as u128) << (64 - rotation_degree));
    F::from(rotated_value as u64)
}
