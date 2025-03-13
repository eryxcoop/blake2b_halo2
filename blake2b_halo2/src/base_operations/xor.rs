use halo2_proofs::circuit::AssignedCell;
use crate::base_operations::decompose_8::Decompose8Config;
use super::*;

pub trait Xor<F: PrimeField> {
    fn populate_xor_lookup_table(
        &mut self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    // [Inigo comment] weird name - is there an unoptimized function?
    fn generate_xor_rows_from_cells_optimized(
        &mut self,
        region: &mut Region<F>,
        offset: &mut usize,
        previous_cell: &AssignedCell<F, F>,
        cell_to_copy: &AssignedCell<F, F>,
        decompose_8_config: &mut Decompose8Config,
        use_previous_cell: bool,
    ) -> Result<[AssignedCell<F, F>; 9], Error>;
}