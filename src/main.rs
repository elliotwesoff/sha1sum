use std::{env, fmt::Display, io::{self, BufReader, Cursor, Read}};

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

    pub fn digest(&self) -> String {
        format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.part0, self.part1, self.part2, self.part3, self.part4
        )
    }

    pub fn ingest(&mut self, stream: &mut Vec<u8>) -> io::Result<()> {
        self.pad_message(stream);
        let mut stream_reader = BufReader::new(Cursor::new(stream));
        let mut n = 0;
        while n < 64 {
            let mut buf = [0u8; 64];
            let mut chunk = stream_reader.by_ref().take(64); // 512 bits
            n = chunk.read(&mut buf)?;
            self.ingest_block(&buf);
        }
        Ok(())
    }

    fn ingest_block(&mut self, block: &[u8]) {
        // 1. Prepare the message schedule (calculated dynamically)

        // 2. Initialize the first five working variables (inc. temp var T)
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
                    .wrapping_add(self.W(&block, t));

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

    fn pad_message(&self, message: &mut Vec<u8>) {
        let msg_len = message.len();
        let msg_len_64: u64 = msg_len.try_into().unwrap();
        let rem = msg_len % 64;
        let new_size = msg_len - rem + 64;
        message.resize(new_size, 0);
        message[msg_len] = 0x80; // append "1" bit to msg
        message[new_size - 8..].copy_from_slice(msg_len_64.to_be_bytes().as_ref());
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

    #[inline]
    fn rotl_u32(&self, v: u32, n: u8) -> u32 {
        // TODO: is there something equivalent in std?
        (v << n) | (v >> (32 - n))
    }

    #[inline]
    fn ch(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline]
    fn parity(&self, x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    #[inline]
    fn maj(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[allow(non_snake_case)]
    fn K(&self, t: u32) -> u32 {
        match t {
            0..20 => 0x5a827999,
            20..40 => 0x6ed9eba1,
            40..60 => 0x8f1bbcdc,
            60..80 => 0xca62c1d6,
            _ => panic!("invalid t provided to K(): {}", t)
        }
    }

    #[allow(non_snake_case)]
    fn W(&self, block: &[u8], t: u32) -> u32 {
        match t {
            0..16 => {
                // "the j'th word of the i'th message block."
                // block is already the i'th message block,
                // so we just take the j'th word (t).
                let i = (t * 4) as usize;
                let j = (i + 4) as usize;
                let r = &block[i..j];
                u32::from_be_bytes(r.try_into().unwrap())
            }, 
            16..80 => {
                let w1 = self.W(block, t - 3);
                let w2 = self.W(block, t - 8);
                let w3 = self.W(block, t - 14);
                let w4 = self.W(block, t - 16);
                self.rotl_u32(w1 ^ w2 ^ w3 ^ w4, 1)
            },
            _ => panic!("invalid t provided to W(): {}", t)
        }
    }
}

impl Display for SHA1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.digest())
    }
}

fn main() {
    // TODO: panic if a file *and* data on stdin are both given

    let mut args = env::args().skip(1); // skip program name
    let path = args.next().unwrap_or(String::from(""));
    dbg!(&path);

    let mut sha1 = SHA1::new();
    let mut buf: Vec<u8> = vec![];
    io::stdin().lock().read_to_end(&mut buf).expect("can't read from stdin");
    sha1.ingest(&mut buf).expect("couldn't ingest input");

    println!("{}", sha1);
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn digest_works_1() {
        let mut sha1 = SHA1::new();
        sha1.part0 = 0x01010101;
        sha1.part1 = 0x02020202;
        sha1.part2 = 0x03030303;
        sha1.part3 = 0x04040404;
        sha1.part4 = 0x05050505;
        let expected = "0101010102020202030303030404040405050505";
        assert_eq!(expected, sha1.digest());
    }

    #[test]
    fn digest_works_2() {
        let mut sha1 = SHA1::new();
        sha1.part0 = 0xaaaaaaaa;
        sha1.part1 = 0xbbbbbbbb;
        sha1.part2 = 0xcccccccc;
        sha1.part3 = 0xdddddddd;
        sha1.part4 = 0xeeeeeeee;
        let expected = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee";
        assert_eq!(expected, sha1.digest());
    }

    #[test]
    fn ingest_works_1() {
        let mut sha1 = SHA1::new();
        let mut input: Vec<u8> = vec![];
        sha1.ingest(&mut input).expect("uh oh");
        assert_eq!("adc83b19e793491b1c6ea0fd8b46cd9f32e592fc", sha1.digest());
    }

    #[test]
    fn ingest_works_2() {
        let mut sha1 = SHA1::new();
        let mut input: Vec<u8> = vec!['t' as u8, 'e' as u8, 's' as u8, 't' as u8];
        sha1.ingest(&mut input).expect("uh oh");
        assert_eq!("4e1243bd22c66e76c2ba9eddc1f91394e57f9f83", sha1.digest());
    }

    // #[test]
    // fn ingest_works_3() {
    //     let mut sha1 = SHA1::new();
    //     sha1.ingest(
    //         "this is a longer message to be digested that causes multiple 512-bit blocks to be processed".as_bytes(),
    //     ).expect("uh oh");
    //     assert_eq!("4d3cbe140a6d1709afea5b53664cd1875f0d5897", sha1.digest());
    // }

    #[test]
    fn pad_message_works_1() {
        let sha1 = SHA1::new();
        let mut message = vec!['a' as u8, 'b' as u8, 'c' as u8];
        let mut expected = [0u8; 64];

        expected[..3].copy_from_slice(b"abc");
        expected[3] = 0x80;
        expected[63] = 3;

        sha1.pad_message(&mut message);
        assert_eq!(
            message.len(), expected.len(),
            "output length of {} is incorrect, should be {}", message.len(), expected.len()
        );
    }

    #[test]
    fn pad_message_works_2() {
        let sha1 = SHA1::new();
        let mut message = vec!['a' as u8, 'b' as u8, 'c' as u8];
        let mut expected = [0u8; 64];

        expected[..3].copy_from_slice(b"abc");
        expected[3] = 0x80;
        expected[63] = 3;

        sha1.pad_message(&mut message);
        compare_padded_outputs(&expected, &message);
    }

    #[test]
    fn pad_message_works_3() {
        let sha1 = SHA1::new();
        let msg = "this is a longer message to be digested that causes multiple 512-bit blocks to be processed";
        let len = msg.len();
        let mut message: Vec<u8> = msg.as_bytes().iter().copied().collect();
        let mut expected = [0u8; 128];

        expected[..len].copy_from_slice(msg.as_bytes());
        expected[len] = 0x80;
        expected[127] = len.try_into().unwrap();

        sha1.pad_message(&mut message);
        assert_eq!(
            expected.len(), message.len(),
            "output length of {} is incorrect, should be {}", message.len(), expected.len()
        );
    }

    #[test]
    fn pad_message_works_4() {
        let sha1 = SHA1::new();
        let msg = "this is a longer message to be digested that causes multiple 512-bit blocks to be processed";
        let len = msg.len();
        let mut message: Vec<u8> = msg.as_bytes().iter().copied().collect();
        let mut expected = [0u8; 128];

        expected[..len].copy_from_slice(msg.as_bytes());
        expected[len] = 0x80;
        expected[127] = len.try_into().unwrap();

        sha1.pad_message(&mut message);
        compare_padded_outputs(&expected, &message);
    }

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
    fn f_works_1() {
        todo!()
    }

    #[test]
    fn f_works_2() {
        todo!()
    }

    #[test]
    fn f_works_3() {
        todo!()
    }

    #[test]
    fn f_works_4() {
        todo!()
    }

    #[test]
    fn f_works_5() {
        todo!()
    }

    #[test]
    fn w_works() {
        todo!()
    }

    fn compare_padded_outputs(expected: &[u8], actual: &[u8]) {
        assert_eq!(
            expected.len(), actual.len(),
            "not comparing arrays of differing lengths"
        );
        for (i, x) in actual.iter().enumerate() {
            let expected = expected[i];
            assert_eq!(
                expected, *x,
                "padded output is incorrect at index {}/{} ({} != {}; expected != actual)",
                i, actual.len() - 1, expected, *x
            );
        }
    }
}
