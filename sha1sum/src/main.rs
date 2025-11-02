// SHA-1 notes:
// msg size (bits): < 2^64
// block size (bits): 512
// word size (bits): 32
// message digest size (bits): 160
// 
// SHA-1 operates on 32-bit words.
//
// SHA-1 uses a sequence of logical functions, f0, f1,…, f79.  Each function ft, where 0 <= t <= 79, 
// operates on three 32-bit words, x, y, and z, and produces a 32-bit word as output.  The function ft 
// (x, y, z) is defined as follows:
//
//  f_t(x, y, z) = {
//    Ch(x,y,z)        = (x ^ y) xor (!x ^ z)                   0  <= t <= 19
//    Parity(x, y, z)  = x xor y xor z                          20 <= t <= 39
//    Maj(x, y, z)     = (x ^ y) xor (x ^ z) xor (y ^ z)        40 <= t <= 59
//    Parity(x, y, z)  = x xor y xor z                          60 <= t <= 79
//  }
//
// SHA-1 Constants:
//
//  K_t = {
//      5a827999            0 <= t <= 19
//      6ed9eba1            20 <= t <= 39
//      8f1bbcdc            40 <= t <= 59
//      ca62c1d6            60 <= t <= 79
//  }
//
// The message must be padded so that the padded message is a multiple of 512 bytes.
//
// In example 5.1.1, 423 + 24 + 64 + 1 = 512
//
// After padding, assert that padded message length mod 512 == 0.
//
// 5.2 Parsing the message
//
// The padded message is parsed into N 512-bit blocks, M^(1), ..., M^(N).
//  * 512 bits => 64 bytes
//
// 5.3 Setting the initial hash value, H^(0)
//
// H_0^(0) = 67452301
// H_1^(0) = efcdab89
// H_2^(0) = 98badcfe
// H_3^(0) = 10325476
// H_4^(0) = c3d2e1f0

fn main() {
    println!("Hello, world!");
}
