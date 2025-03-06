// This is the main chip for the Blake2b hash function. It is responsible for the entire hash computation.
// It contains all the necessary chips and some extra columns.
//
// This optimization uses addition with 4 limbs instead of 8, which allows the circuit to have
// one less column (the carry column). This is because the addition chip of 8 bits uses 10 columns
// (the maximum amount of columns any chip uses) and the addition chip of 4 bits uses 6 columns.
// It also computes xor with a table that precomputes all the possible 8-bit operands.
