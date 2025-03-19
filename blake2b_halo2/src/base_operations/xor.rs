use super::*;
use crate::base_operations::decompose_8::Decompose8Config;
use crate::types::AssignedNative;

pub trait Xor {
    fn populate_xor_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    fn generate_xor_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: &AssignedNative<F>,
        cell_to_copy: &AssignedNative<F>,
        decompose_8_config: &Decompose8Config,
        use_previous_cell: bool,
    ) -> Result<[AssignedNative<F>; 9], Error>;
}
