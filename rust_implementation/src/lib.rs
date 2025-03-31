// DATA
// +--------------+------------------+
// |              | BLAKE2b          |
// +--------------+------------------+
// | Bits in word | w  = 64          |
// | Rounds in F  | r  = 12          |
// | Block bytes  | bb = 128         |
// | Hash bytes   | 1 <= nn <= 64    |
// | Key bytes    | 0 <= kk <= 64    |
// | Input bytes  | 0 <= ll < 2**128 |
// +--------------+------------------+
// | G Rotation   | (R1, R2, R3, R4) |
// |  constants   | (32, 24, 16, 63) |
// +--------------+------------------+

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
pub mod tests;

// Constants
const BLAKE2B_IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// Context

struct Blake2bCtx {
    iteration_buffer: [u8; 128],     // input buffer
    state: [u64; 8], // chained state, it is like the accumulator of the compression function
    processed_bytes_count: [u64; 2], // total number of bytes, low part and high part of the number (message can be up to 2^128)
    buffer_pointer: usize,           // pointer for b[]
}

impl Blake2bCtx {
    fn new(key: &mut [u8], outlen: usize) -> Self {
        let mut state: [u64; 8] = BLAKE2B_IV;
        state[0] = state[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;
        Self {
            iteration_buffer: [0; 128],
            state,
            processed_bytes_count: [0; 2],
            buffer_pointer: 0,
        }
    }
}

// Hash Function

pub fn blake2b(out: &mut [u8], key: &mut [u8], input_message: &mut [u8]) -> i32 {
    if out.is_empty() || out.len() > 64 || key.len() > 64 {
        panic!("Illegal input parameters")
    }
    let mut ctx = Blake2bCtx::new(key, out.len());

    if !key.is_empty() {
        blake2b_update(&mut ctx, key);
        ctx.buffer_pointer = 128;
    }
    blake2b_update(&mut ctx, input_message);
    blake2b_final(&mut ctx, out);

    0
}

fn rotr_64(x: u64, n: u8) -> u64 {
    (x >> n) ^ (x << (64 - n))
}

fn b2b_get64(p: &[u8]) -> u64 {
    (p[0] as u64)
        ^ (p[1] as u64) << 8
        ^ (p[2] as u64) << 16
        ^ (p[3] as u64) << 24
        ^ (p[4] as u64) << 32
        ^ (p[5] as u64) << 40
        ^ (p[6] as u64) << 48
        ^ (p[7] as u64) << 56
}

fn b2b_g(a: usize, b: usize, c: usize, d: usize, x: u64, y: u64, state: &mut [u64; 16]) {
    state[a] = ((state[a] as u128 + state[b] as u128 + x as u128) % (1 << 64)) as u64;
    state[d] = rotr_64(state[d] ^ state[a], 32);
    state[c] = ((state[c] as u128 + state[d] as u128) % (1 << 64)) as u64;
    state[b] = rotr_64(state[b] ^ state[c], 24);
    state[a] = ((state[a] as u128 + state[b] as u128 + y as u128) % (1 << 64)) as u64;
    state[d] = rotr_64(state[d] ^ state[a], 16);
    state[c] = ((state[c] as u128 + state[d] as u128) % (1 << 64)) as u64;
    state[b] = rotr_64(state[b] ^ state[c], 63);
}

fn blake2b_update(ctx: &mut Blake2bCtx, input: &mut [u8]) {
    for byte in input {
        const BUFFER_SIZE: u64 = 128;
        if ctx.buffer_pointer == BUFFER_SIZE as usize {
            ctx.processed_bytes_count[0] += BUFFER_SIZE;
            if ctx.processed_bytes_count[0] < BUFFER_SIZE {
                ctx.processed_bytes_count[1] += 1; // Increments the higher part when overflows the lower
            }
            blake2b_compress(ctx, false);
            ctx.buffer_pointer = 0;
        }
        ctx.iteration_buffer[ctx.buffer_pointer] = *byte;
        ctx.buffer_pointer += 1;
    }
}

fn blake2b_compress(ctx: &mut Blake2bCtx, last: bool) {
    let mut accumulative_state: [u64; 16] = [0; 16];
    let mut current_block_words: [u64; 16] = [0; 16];

    accumulative_state[..8].copy_from_slice(&ctx.state);
    accumulative_state[8..16].copy_from_slice(&BLAKE2B_IV);
    // First, we fill the array v:
    // - The first 8 positions are the current state
    // - The following 8 positions are the IV values of the compression function, which will always be the same

    accumulative_state[12] ^= ctx.processed_bytes_count[0]; // This is the low part of the number of processed bytes
    accumulative_state[13] ^= ctx.processed_bytes_count[1]; // and this is the high part.

    if last {
        accumulative_state[14] = !accumulative_state[14]
    }

    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        // This simply formats the 128 bytes of the buffer in 16 u64
        current_block_words[i] = b2b_get64(&ctx.iteration_buffer[8 * i..8 * i + 8]);
    }

    for i in 0..12 {
        b2b_g(
            0,
            4,
            8,
            12,
            current_block_words[SIGMA[i][0]],
            current_block_words[SIGMA[i][1]],
            &mut accumulative_state,
        );
        b2b_g(
            1,
            5,
            9,
            13,
            current_block_words[SIGMA[i][2]],
            current_block_words[SIGMA[i][3]],
            &mut accumulative_state,
        );
        b2b_g(
            2,
            6,
            10,
            14,
            current_block_words[SIGMA[i][4]],
            current_block_words[SIGMA[i][5]],
            &mut accumulative_state,
        );
        b2b_g(
            3,
            7,
            11,
            15,
            current_block_words[SIGMA[i][6]],
            current_block_words[SIGMA[i][7]],
            &mut accumulative_state,
        );
        b2b_g(
            0,
            5,
            10,
            15,
            current_block_words[SIGMA[i][8]],
            current_block_words[SIGMA[i][9]],
            &mut accumulative_state,
        );
        b2b_g(
            1,
            6,
            11,
            12,
            current_block_words[SIGMA[i][10]],
            current_block_words[SIGMA[i][11]],
            &mut accumulative_state,
        );
        b2b_g(
            2,
            7,
            8,
            13,
            current_block_words[SIGMA[i][12]],
            current_block_words[SIGMA[i][13]],
            &mut accumulative_state,
        );
        b2b_g(
            3,
            4,
            9,
            14,
            current_block_words[SIGMA[i][14]],
            current_block_words[SIGMA[i][15]],
            &mut accumulative_state,
        );
    }

    /*for i in 0..16 {
        println!("accumulative_state[{}]: {:x}", i, accumulative_state[i]);
    }*/
    for i in 0..8 {
        ctx.state[i] ^= accumulative_state[i] ^ accumulative_state[i + 8];
    }
}

fn blake2b_final(ctx: &mut Blake2bCtx, out: &mut [u8]) {
    ctx.processed_bytes_count[0] += ctx.buffer_pointer as u64;

    if ctx.processed_bytes_count[0] < ctx.buffer_pointer as u64 {
        ctx.processed_bytes_count[1] += 1; // Increments the higher part when overflows the lower
    }

    while ctx.buffer_pointer < 128 {
        ctx.iteration_buffer[ctx.buffer_pointer] = 0;
        ctx.buffer_pointer += 1;
    }
    blake2b_compress(ctx, true);

    #[allow(clippy::needless_range_loop)]
    for i in 0..out.len() {
        out[i] = ((ctx.state[i >> 3] >> (8 * (i & 7))) & 0xFF) as u8;
    }
}
