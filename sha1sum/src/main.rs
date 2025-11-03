// SHA-1 notes:
// msg size (bits): < 2^64
// block size (bits): 512
// word size (bits): 32
// message digest size (bits): 160
// 
// SHA-1 operates on 32-bit words.
//
// For the secure hash algorithms, the size of the message block - m bits - depends on the 
// algorithm. 
// a) For SHA-1, SHA-224 and SHA-256, each message block has 512 bits, which are 
// represented as a sequence of sixteen 32-bit words.

struct SHA1 {
    part0: u32,
    part1: u32,
    part2: u32,
    part3: u32,
    part4: u32
}

impl SHA1 {
    pub fn new() -> Self {
        SHA1 {
            part0: 0x67452301,
            part1: 0xefcdab89,
            part2: 0x98badcfe,
            part3: 0x10325476,
            part4: 0xc3d2e1f0
        }
    }
}

impl Into<String> for SHA1 {
    fn into(self) -> String {
        let nums = [self.part0, self.part1, self.part2, self.part3, self.part4];
        // let s = nums.iter().map(|n| format!("{:x}", n)).collect::<String>();
        nums.iter().map(|n| {
            let s = format!("{:08x}", n);
            println!("{}", s);
            s
        })
        .collect::<String>()
    }
}

fn pad_block(msg: &[u8]) -> [u8; 64] {
    let len = msg.len();
    let len_64: u64 = len.try_into().unwrap();
    let mut padded_msg = [0; 64]; // initialized block comes with pre-padding :3

    // TODO: this may not be correct. does the 1 bit always
    //       align with an addressable memory boundary?   
    padded_msg[..len].clone_from_slice(&msg);
    padded_msg[len] = 0x80; // place a 1 bit after the msg

    // add the 64 bit length to the end of the block
    // TODO: is this a hack? can we do this better?
    for (i, x) in len_64.to_ne_bytes().iter().enumerate() {
        padded_msg[63 - i] = *x;
    }

    padded_msg
}

fn f(x: u32, y: u32, z: u32, t: u32) -> u32 {
    match t {
        0..20 => ch(x, y, z),
        20..40 => parity(x, y, z),
        40..60 => maj(x, y, z),
        60..80 => parity(x, y, z),
        _ => panic!("invalid t parameter for f(): {}", t)
    }
}

fn rotl_u32(v: u32, n: u8) -> u32 {
   (v << n) | (v >> (32 - n))
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn _add(a: u32, b: u32) -> u32 {
    // let c: u64 = (a + b).try_into().unwrap();
    // (c % 0x00000001000000).try_into().unwrap()
    a + b
}

fn K(t: u32) -> u32 {
    match t {
        0..20 => 0x5a827999,
        20..40 => 0x6ed9eba1,
        40..60 => 0x8f1bbcdc,
        60..80 => 0xca62c1d6,
        _ => panic!("invalid t parameter for K(): {}", t)
    }
}

fn W(t: u32) -> u32 {
    match t {
        0..16 => 0,
        16..80 => 0,
        _ => panic!("invalid t parameter for W(): {}", t)
    }
}

fn main() {
    let mut h = SHA1::new();
    let test_string = String::from("test");

    // in this instance, there is only *one* message block.
    // the entire message is less than 512 bits (512b / 8b == 64B).
    //
    // in the eventual case, we'll need to implement the "for i=1 to N"
    // to iterate over all 512b blocks of M, like in the spec.

    // 1. Prepare the message schedule
    let msg_padded = pad_block(&test_string.as_bytes());
    println!("test str: {:?}", test_string.as_bytes());
    println!("test str padded: {:?}", msg_padded);

    // 2. Initialize the first five working variables
    let mut T: u32;
    let mut a = h.part0;
    let mut b = h.part1;
    let mut c = h.part2;
    let mut d = h.part3;
    let mut e = h.part4;

    // 3. Process the eighty schedule messages
    for t in 0..80 {
        // chatgpt claims that the wrap around for addition of 32 bit
        // ints works the same as addition mod 2^32. if we get issues,
        // look into this first.
        T = rotl_u32(a, 5)
                .wrapping_add(f(b, c, d, t))
                .wrapping_add(e)
                .wrapping_add(K(t))
                .wrapping_add(W(t));

        e = d;
        d = c;
        c = rotl_u32(b, 30);
        b = a;
        a = T;
    }

    // 4. Compute the ith intermediate hash value, H^(i)
    h.part0 = a.wrapping_add(h.part0);
    h.part1 = b.wrapping_add(h.part1);
    h.part2 = c.wrapping_add(h.part2);
    h.part3 = d.wrapping_add(h.part3);
    h.part4 = e.wrapping_add(h.part4);

    let digest: String = h.into();
    println!("digested: {}", digest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_block_works() {
        todo!()
    }

    #[test]
    fn rotl_u32_works_1() {
        let x = 0xff000000;
        let n = 8;
        let expected = 0x000000ff;
        let actual = rotl_u32(x, n);
        assert_eq!(expected, actual);
    }

    #[test]
    fn rotl_u32_works_2() {
        let x = 0x00050500;
        let n = 16;
        let expected = 0x05000005;
        let actual = rotl_u32(x, n);
        assert_eq!(expected, actual);
    }

    #[test]
    fn rotl_u32_works_3() {
        let x = 0x80000000;
        let n = 1;
        let expected = 0x00000001;
        let actual = rotl_u32(x, n);
        assert_eq!(expected, actual);
    }

    #[test]
    fn ch_works() {
        assert_eq!(328, ch(100, 200, 300));
    }

    #[test]
    fn parity_works() {
        assert_eq!(384, parity(100, 200, 300));
    }

    #[test]
    fn maj_works() {
        assert_eq!(108, maj(100, 200, 300));
    }

    #[test]
    fn k_works_1() {
        assert_eq!(0x5a827999, K(0));
        assert_eq!(0x5a827999, K(10));
        assert_eq!(0x5a827999, K(19));
    }

    #[test]
    fn k_works_2() {
        assert_eq!(0x6ed9eba1, K(20));
        assert_eq!(0x6ed9eba1, K(30));
        assert_eq!(0x6ed9eba1, K(39));
    }

    #[test]
    fn k_works_3() {
        assert_eq!(0x8f1bbcdc, K(40));
        assert_eq!(0x8f1bbcdc, K(50));
        assert_eq!(0x8f1bbcdc, K(59));
    }

    #[test]
    fn k_works_4() {
        assert_eq!(0xca62c1d6, K(60));
    }

    #[test]
    fn w_works() {
        todo!()
    }
}
