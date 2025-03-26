use super::*;
use crate::auxiliar_functions::*;
use halo2_proofs::halo2curves::bn256::Fr;
use ff::Field;
use std::marker::PhantomData;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::types::AssignedNative;

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