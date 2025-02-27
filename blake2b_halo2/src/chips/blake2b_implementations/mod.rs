use super::*;

/// This is the chip with all the optimizations, toggled with features
pub mod blake2b_chip;

/// These are the separated optimizations, they exist with benchmarking purposes
pub mod blake2b_chip_a;
pub mod blake2b_chip_b;
pub mod blake2b_chip_c;
pub mod blake2b_chip_optimization;
