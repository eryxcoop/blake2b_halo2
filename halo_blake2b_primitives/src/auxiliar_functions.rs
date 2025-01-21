use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;

pub fn trash() -> Value<Fr> {
    zero()
}
pub fn max_u64() -> Value<Fr> {
    value_for((1u128 << 64) - 1)
}
pub fn max_u16() -> Value<Fr> {
    let number = (1u64 << 16) - 1;
    value_for(number)
}

pub fn max_u24() -> Value<Fr> {
    value_for((1u64 << 24) - 1)
}
pub fn max_u8() -> Value<Fr> {
    value_for((1u64 << 8) - 1)
}
pub fn max_u40() -> Value<Fr> {
    value_for((1u128 << 40) - 1)
}

pub fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
pub fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}

pub fn spread(mut n: u16) -> u32 {
    let mut spread: u32 = 0;
    let mut position: u32 = 0;

    while n != 0 {
        // Extract the least significant bit
        let bit: u32 = (n & 1u16) as u32;
        // Shift it to the appropriate position in the spread number
        spread |= bit << (2 * position);
        // Move to the next bit of the input number
        n >>= 1;
        // Increment the spread position
        position += 1;
    }

    spread
}

pub fn value_for<T, F>(number: T) -> Value<F>
where
    T: Into<u128>,
    F: Field + From<u64>,
{
    Value::known(field_for(number))
}

pub fn field_for<T, F>(number: T) -> F
where
    T: Into<u128>,
    F: Field + From<u64>,
{
    let number: u128 = number.into();
    let lo: u64 = (number % (1u128 << 64)) as u64;
    let hi: u64 = (number / (1u128 << 64)) as u64;
    let field_pow64 = F::from(1 << 63) * F::from(2);
    F::from(hi) * field_pow64 + F::from(lo)
}

pub fn generate_row_8bits<T, F>(number: T) -> [Value<F>; 10]
where
    F: Field + From<u64>,
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

pub fn convert_to_u64<F: PrimeField>(a: F) -> u64 {
    let binding = a.to_repr();
    let a_bytes = binding.as_ref();

    let mut a_value: u64 = 0;
    for (i, b) in a_bytes[0..8].iter().enumerate() {
        a_value += ((*b as u64) * (1u64 << (8 * i))) as u64;
    }
    a_value
}

pub fn xor_field_elements<F: PrimeField>(a: F, b: F) -> F {
    let a_value = convert_to_u64(a);
    let b_value = convert_to_u64(b);

    F::from(a_value ^ b_value)
}
