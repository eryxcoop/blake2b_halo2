use super::*;

/// This is the chip with all the optimizations, toggled with features
pub mod blake2b_chip;

/// These are the separated optimizations, they exist with benchmarking purposes
pub mod blake2b_chip_opt_4_limbs;
pub mod blake2b_chip_opt_recycle;
pub mod blake2b_chip_opt_spread;
pub mod blake2b_instructions;
