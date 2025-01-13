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
    b: [u8; 128], // input buffer
    h: [u64; 8],  // chained state, es como el acumulador de la compression function
    t: [u64; 2], // total number of bytes, low part y high part del número (pq el mensaje puede ser de hasta 2^128 bytes)
    c: usize,    // pointer for b[]
}

impl Blake2bCtx {
    fn new(key: &mut Vec<u8>, outlen: usize) -> Self {
        let mut h: [u64; 8] = BLAKE2B_IV;
        h[0] = h[0] ^ 0x01010000 ^ (key.len() << 8) as u64 ^ outlen as u64;

        Self {
            b: [0; 128],
            h,
            t: [0; 2],
            c: 0,
        }
    }
}

// Hash Function

pub fn blake2b(out: &mut Vec<u8>, key: &mut Vec<u8>, input_message: &mut Vec<u8>) -> i32 {
    if out.is_empty() || out.len() > 64 || key.len() > 64 {
        panic!("Illegal input parameters")
    }
    let mut ctx = Blake2bCtx::new(key, out.len());

    if !key.is_empty() {
        blake2b_update(&mut ctx, key);
        ctx.c = 128;
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

fn b2b_g(a: usize, b: usize, c: usize, d: usize, x: u64, y: u64, v: &mut [u64; 16]) {
    v[a] = ((v[a] as u128 + v[b] as u128 + x as u128) % (1 << 64)) as u64;
    v[d] = rotr_64(v[d] ^ v[a], 32);
    v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
    v[b] = rotr_64(v[b] ^ v[c], 24);
    v[a] = ((v[a] as u128 + v[b] as u128 + y as u128) % (1 << 64)) as u64;
    v[d] = rotr_64(v[d] ^ v[a], 16);
    v[c] = ((v[c] as u128 + v[d] as u128) % (1 << 64)) as u64;
    v[b] = rotr_64(v[b] ^ v[c], 63);
}

fn blake2b_update(ctx: &mut Blake2bCtx, input: &mut Vec<u8>) {
    for i in 0..input.len() {
        if ctx.c == 128 {
            ctx.t[0] += ctx.c as u64;
            if ctx.t[0] < ctx.c as u64 {
                ctx.t[1] += 1;
            }
            blake2b_compress(ctx, false);
            ctx.c = 0;
        }
        ctx.b[ctx.c] = input[i];
        ctx.c += 1;
    }
}

fn blake2b_compress(ctx: &mut Blake2bCtx, last: bool) {
    let mut v: [u64; 16] = [0; 16];
    let mut m: [u64; 16] = [0; 16];

    v[..8].copy_from_slice(&ctx.h[..8]);
    v[8..16].copy_from_slice(&BLAKE2B_IV[..8]);
    // for i in 0..8 {
    //     v[i] = ctx.h[i];
    //     v[i + 8] = BLAKE2B_IV[i];
    // }

    v[12] ^= ctx.t[0];
    v[13] ^= ctx.t[1];

    if last {
        v[14] = !v[14]
    }

    for i in 0..16 {
        m[i] = b2b_get64(&ctx.b[8 * i..8 * i + 8]);
    }

    for i in 0..12 {
        b2b_g(0, 4, 8, 12, m[SIGMA[i][0]], m[SIGMA[i][1]], &mut v);
        b2b_g(1, 5, 9, 13, m[SIGMA[i][2]], m[SIGMA[i][3]], &mut v);
        b2b_g(2, 6, 10, 14, m[SIGMA[i][4]], m[SIGMA[i][5]], &mut v);
        b2b_g(3, 7, 11, 15, m[SIGMA[i][6]], m[SIGMA[i][7]], &mut v);
        b2b_g(0, 5, 10, 15, m[SIGMA[i][8]], m[SIGMA[i][9]], &mut v);
        b2b_g(1, 6, 11, 12, m[SIGMA[i][10]], m[SIGMA[i][11]], &mut v);
        b2b_g(2, 7, 8, 13, m[SIGMA[i][12]], m[SIGMA[i][13]], &mut v);
        b2b_g(3, 4, 9, 14, m[SIGMA[i][14]], m[SIGMA[i][15]], &mut v);
    }

    for i in 0..8 {
        ctx.h[i] ^= v[i] ^ v[i + 8];
    }
}

fn blake2b_final(ctx: &mut Blake2bCtx, out: &mut Vec<u8>) {
    ctx.t[0] += ctx.c as u64;

    if ctx.t[0] < ctx.c as u64 {
        ctx.t[1] += 1;
    }

    while ctx.c < 128 {
        ctx.b[ctx.c] = 0;
        ctx.c += 1;
    }
    blake2b_compress(ctx, true);
    for i in 0..out.len() {
        out[i] = ((ctx.h[i >> 3] >> (8 * (i & 7))) & 0xFF) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json;

    #[derive(Deserialize, Debug)]
    struct TestCase {
        hash: String,
        #[serde(rename = "in")]
        input: String,
        key: String,
        out: String,
    }

    #[test]
    fn test_hashes() {
        let file_content =
            std::fs::read_to_string("./test_vector.json").expect("Failed to read file");
        let test_cases: Vec<TestCase> =
            serde_json::from_str(&file_content).expect("Failed to parse JSON");

        for (i, case) in test_cases.iter().enumerate() {
            println!("Running test case {}", i);
            run_test(&case.hash, &case.input, &case.key, &case.out);
        }
    }

    fn run_test(hash: &str, input: &str, key: &str, expected: &str) {
        let mut input_message = hex_to_bytes(input);
        let mut key = hex_to_bytes(key);
        let expected_out = hex_to_bytes(expected);
        let mut buffer_out: Vec<u8> = Vec::new();
        buffer_out.resize(expected_out.len(), 0);

        let result = blake2b(&mut buffer_out, &mut key, &mut input_message);

        assert_eq!(
            buffer_out, expected_out,
            "Test failed for input: {:?}, key: {:?}",
            input, key
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
