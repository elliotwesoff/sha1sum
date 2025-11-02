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


struct SHA1Hash {
    part0: u32,
    part1: u32,
    part2: u32,
    part3: u32,
    part4: u32
}

impl SHA1Hash {
    pub fn new() -> Self {
        SHA1Hash {
            part0: 0x67452301,
            part1: 0xefcdab89,
            part2: 0x98badcfe,
            part3: 0x10325476,
            part4: 0xc3d2e1f0
        }
    }
}

impl Into<String> for SHA1Hash {
    fn into(self) -> String {
        let nums = [self.part0, self.part1, self.part2, self.part3, self.part4];
        nums.iter().map(|n| n.to_string()).collect::<String>()
    }
}

fn pad_block(msg: &[u8]) -> [u8; 512] {
    let len = msg.len();
    let len_64: u64 = len.try_into().unwrap();
    let mut padded_msg = [0; 512]; // initialized block is pre-padded

    padded_msg[..len].clone_from_slice(&msg);
    padded_msg[len] = 0x80; // place a 1 bit after the msg

    // add the 64 bit length to the end of the block
    for (i, x) in len_64.to_ne_bytes().iter().enumerate() {
        padded_msg[511 - i] = *x;
    }

    padded_msg
}

fn f_t(i: i32, x: u32, y: u32, z: u32) -> u32 {
    todo!()
}

fn main() {
    let mut sha1_hash = SHA1Hash::new();
    let test_string = String::from("test");

    // 1. Prepare the message schedule
    let msg_padded = pad_block(&test_string.as_bytes());
    println!("test str: {:?}", test_string.as_bytes());
    println!("test str padded: {:?}", msg_padded);

    // 2. Initialize the first five working variables
    let mut t: u32;
    let mut a = sha1_hash.part0;
    let mut b = sha1_hash.part1;
    let mut c = sha1_hash.part2;
    let mut d = sha1_hash.part3;
    let mut e = sha1_hash.part4;

    // 3. Process the eighty schedule messages
    for _i in 0..=79 {
        // t = ROTL^5(a) + f_t(b, c, d) + e + K_t + W_t
        e = d;
        d = c;
        // c = ROTL^30(b);
        b = a;
        a = t;
    }

    // 4. Compute the ith intermediate hash value H^(i)
    sha1_hash.part0 = a + sha1_hash.part0;
    sha1_hash.part1 = b + sha1_hash.part1;
    sha1_hash.part2 = c + sha1_hash.part2;
    sha1_hash.part3 = d + sha1_hash.part3;
    sha1_hash.part4 = e + sha1_hash.part4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
