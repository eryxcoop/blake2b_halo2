use super::*;
use crate::auxiliar_functions::*;
use halo2_proofs::halo2curves::bn256::Fr;
use ff::Field;
use std::marker::PhantomData;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::types::{AssignedNative, Blake2bWord};

mod test_blake2b;
mod test_negate;
mod tests_addition;
mod tests_rotation;
mod tests_xor;

impl Decompose8Config {
    /// Given an explicit vector of values, it assigns the full number and the limbs in a row of the trace
    /// row size is T + 1
    /// row[0] is the full number
    /// row[1..T] are the limbs representation of row[0]
    fn populate_row_from_values<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        row: &[Value<F>],
        offset: usize,
        check_decomposition: bool,
    ) -> Result<Vec<AssignedNative<F>>, Error> {
        if check_decomposition {
            self.q_decompose.enable(region, offset)?;
            self.q_range.enable(region, offset)?;
        }
        let full_number =
            region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0])?;

        let limbs = (0..8)
            .map(|i| {
                region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || row[i + 1])
            })
            .collect::<Result<Vec<_>, _>>()?;

        //return the full number and the limbs
        Ok(std::iter::once(full_number).chain(limbs).collect())
    }
}

pub(crate) fn one() -> Value<Fr> {
    Value::known(Fr::ONE)
}
pub(crate) fn zero() -> Value<Fr> {
    Value::known(Fr::ZERO)
}

pub(crate) fn blake2b_value_for(number: u64) -> Value<Blake2bWord> {
    Value::known(Blake2bWord(number))
}

pub(crate) fn value_for<T, F>(number: T) -> Value<F>
where
    T: Into<u128>,
    F: PrimeField,
{
    Value::known(field_for(number))
}

pub(crate) fn generate_row_8bits<T, F>(number: T) -> [Value<F>; 9]
where
    F: PrimeField,
    T: Into<u128>,
{
    let mut number: u128 = number.into();
    let mut ans = [Value::unknown(); 9];
    ans[0] = value_for(number);
    for ans_item in ans.iter_mut().take(9).skip(1) {
        *ans_item = value_for(number % 256);
        number /= 256;
    }
    ans
}
