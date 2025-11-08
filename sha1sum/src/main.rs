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

use std::io::{self, BufReader, Read};

struct SHA1 {
    part0: u32,
    part1: u32,
    part2: u32,
    part3: u32,
    part4: u32,
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

    pub fn ingest(&mut self, stream: &[u8]) -> io::Result<()> {
        let mut stream_reader = BufReader::new(stream);
        let mut buf = [0u8; 64];
        loop {
            let mut chunk = stream_reader.by_ref().take(64); // 512 bits
            let n = chunk.read(&mut buf)?;
            self.ingest_block(&buf);
            if n < 64 {
                break;
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        let nums = [self.part0, self.part1, self.part2, self.part3, self.part4];
        nums.iter().map(|n| format!("{:08x}", n))
                   .collect::<String>()
    }

    fn ingest_block(&mut self, block: &[u8]) {
        // 1. Prepare the message schedule
        //    ??? TODO

        // 2. Initialize the first five working variables
        let mut tmp: u32;
        let mut a = self.part0;
        let mut b = self.part1;
        let mut c = self.part2;
        let mut d = self.part3;
        let mut e = self.part4;

        // 3. Process the eighty schedule messages
        for t in 0..80 {
            // chatgpt claims that the wrap around for addition of 32 bit
            // ints works the same as addition mod 2^32. if we get issues,
            // look into this first.
            tmp = self.rotl_u32(a, 5)
                    .wrapping_add(self.f(b, c, d, t))
                    .wrapping_add(e)
                    .wrapping_add(self.K(t))
                    .wrapping_add(self.W(t));

            e = d;
            d = c;
            c = self.rotl_u32(b, 30);
            b = a;
            a = tmp;
        }

        // 4. Compute the ith intermediate hash value, H^(i)
        self.part0 = a.wrapping_add(self.part0);
        self.part1 = b.wrapping_add(self.part1);
        self.part2 = c.wrapping_add(self.part2);
        self.part3 = d.wrapping_add(self.part3);
        self.part4 = e.wrapping_add(self.part4);
    }

    fn f(&self, x: u32, y: u32, z: u32, t: u32) -> u32 {
        match t {
            0..20 => self.ch(x, y, z),
            20..40 => self.parity(x, y, z),
            40..60 => self.maj(x, y, z),
            60..80 => self.parity(x, y, z),
            _ => panic!("invalid t parameter for f(): {}", t)
        }
    }

    fn rotl_u32(&self, v: u32, n: u8) -> u32 {
       (v << n) | (v >> (32 - n))
    }

    fn ch(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn parity(&self, x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn maj(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn K(&self, t: u32) -> u32 {
        match t {
            0..20 => 0x5a827999,
            20..40 => 0x6ed9eba1,
            40..60 => 0x8f1bbcdc,
            60..80 => 0xca62c1d6,
            _ => panic!("invalid t provided to K(): {}", t)
        }
    }

    fn W(&self, t: u32) -> u32 {
        // TODO
        match t {
            0..16 => 0,
            16..80 => 0,
            _ => panic!("invalid t provided to W(): {}", t)
        }
    }
}

impl Into<String> for SHA1 {
    fn into(self) -> String {
        let nums = [self.part0, self.part1, self.part2, self.part3, self.part4];
        nums.iter().map(|n| format!("{:08x}", n))
                   .collect::<String>()
    }
}

fn main() {
    let mut sha1 = SHA1::new();

    // in this instance, there is only *one* message block.
    // the entire message is less than 512 bits (512b / 8b == 64B).
    let input = String::from("test");

    sha1.ingest(input.as_bytes()).expect("couldn't ingest input");
    println!("{}", sha1.digest());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotl_u32_works_1() {
        let sha1 = SHA1::new();
        let x = 0xff000000;
        let n = 8;
        let expected = 0x000000ff;
        let actual = sha1.rotl_u32(x, n);
        assert_eq!(expected, actual);
    }

    #[test]
    fn rotl_u32_works_2() {
        let sha1 = SHA1::new();
        let x = 0x00050500;
        let n = 16;
        let expected = 0x05000005;
        let actual = sha1.rotl_u32(x, n);
        assert_eq!(expected, actual);
    }

    #[test]
    fn rotl_u32_works_3() {
        let sha1 = SHA1::new();
        let x = 0x80000000;
        let n = 1;
        let expected = 0x00000001;
        let actual = sha1.rotl_u32(x, n);
        assert_eq!(expected, actual);
    }

    #[test]
    fn ch_works() {
        let sha1 = SHA1::new();
        assert_eq!(328, sha1.ch(100, 200, 300));
    }

    #[test]
    fn parity_works() {
        let sha1 = SHA1::new();
        assert_eq!(384, sha1.parity(100, 200, 300));
    }

    #[test]
    fn maj_works() {
        let sha1 = SHA1::new();
        assert_eq!(108, sha1.maj(100, 200, 300));
    }

    #[test]
    fn k_works_1() {
        let sha1 = SHA1::new();
        assert_eq!(0x5a827999, sha1.K(0));
        assert_eq!(0x5a827999, sha1.K(10));
        assert_eq!(0x5a827999, sha1.K(19));
    }

    #[test]
    fn k_works_2() {
        let sha1 = SHA1::new();
        assert_eq!(0x6ed9eba1, sha1.K(20));
        assert_eq!(0x6ed9eba1, sha1.K(30));
        assert_eq!(0x6ed9eba1, sha1.K(39));
    }

    #[test]
    fn k_works_3() {
        let sha1 = SHA1::new();
        assert_eq!(0x8f1bbcdc, sha1.K(40));
        assert_eq!(0x8f1bbcdc, sha1.K(50));
        assert_eq!(0x8f1bbcdc, sha1.K(59));
    }

    #[test]
    fn k_works_4() {
        let sha1 = SHA1::new();
        assert_eq!(0xca62c1d6, sha1.K(60));
    }

    #[test]
    fn w_works() {
        todo!()
    }
}
