/// This is the trait that contains most of the behaviour of the blake2b chips
pub mod blake2b_generic;

/// This is the chip with all the optimizations, toggled with features
pub mod blake2b_chip;
/// These are the separated optimizations
pub mod opt_4_limbs;
pub mod opt_recycle;
pub mod opt_spread;
