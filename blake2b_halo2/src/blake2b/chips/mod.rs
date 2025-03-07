/// This is the chip with all the optimizations, toggled with features
pub mod blake2b_chip;
/// These are the separated optimizations, they exist with benchmarking purposes
pub mod opt_4_limbs;
pub mod opt_recycle;
pub mod opt_spread;