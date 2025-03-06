// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
// It contains all the necessary chips and some extra columns.
//
// This optimization uses addition with 8 limbs and computes xor with a table that precomputes
// all the possible 8-bit operands.
