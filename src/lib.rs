use std::{error::Error, fmt::Display, io::{self, BufReader, Cursor, Read}};

pub struct SHA1 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32
}

impl SHA1 {
    pub fn new() -> Self {
        SHA1 {
            h0: 0x67452301,
            h1: 0xefcdab89,
            h2: 0x98badcfe,
            h3: 0x10325476,
            h4: 0xc3d2e1f0
        }
    }

    pub fn digest(&self) -> String {
        format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.h0, self.h1, self.h2, self.h3, self.h4
        )
    }

    pub fn ingest(&mut self, stream: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let mut stream_reader = BufReader::new(Cursor::new(stream));

        loop {
            let mut buf = [0u8; 64];
            let mut chunk = stream_reader.by_ref().take(64);

            let bytes_read = chunk.read(&mut buf)?;

            match bytes_read {
                0  => return Ok(()),
                64 => {
                    self.ingest_chunk(buf)?;
                    Ok(())
                },
                _  => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad message size, bytes read: {} != 64", bytes_read),
                ))
            }?;
        }
    }

    fn ingest_chunk(&mut self, chunk: [u8; 64]) -> Result<(), Box<dyn Error>> {
        // 1. Prepare the message schedule (W)
        let msg_schedule = self.prepare_message_schedule(chunk)?;

        // 2. Initialize the first five working variables (inc. temp var T)
        let mut tmp: u32;
        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;

        // 3. Process the eighty schedule messages
        for t in 0..80 {
            let t = t as usize;

            tmp = a.rotate_left(5)
                   .wrapping_add(self.f(b, c, d, t))
                   .wrapping_add(e)
                   .wrapping_add(self.K(t))
                   .wrapping_add(msg_schedule[t]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        // 4. Compute the ith intermediate hash value, H^(i)
        self.h0 = a.wrapping_add(self.h0);
        self.h1 = b.wrapping_add(self.h1);
        self.h2 = c.wrapping_add(self.h2);
        self.h3 = d.wrapping_add(self.h3);
        self.h4 = e.wrapping_add(self.h4);

        Ok(())
    }

    pub fn pad_message(&self, message: &mut Vec<u8>, total_size: usize) -> Result<(), Box<dyn Error>> {
        let msg_len = message.len();
        let rem = msg_len % 64;
        let new_size = msg_len - rem + 64; // smooth brain solution v.v
        let total_size_64: u64 = total_size.try_into()?;
        let total_size_64_bytes = (total_size_64 * 8).to_be_bytes(); // len in bits, split into 8 bytes

        message.resize(new_size, 0);
        message[msg_len] = 0x80;
        message[new_size - 8..].copy_from_slice(&total_size_64_bytes);

        Ok(())
    }

    fn prepare_message_schedule(&self, chunk: [u8; 64]) -> Result<[u32; 80], Box<dyn Error>> {
        let mut schedule = [0u32; 80];
        let mut buf_reader = BufReader::new(Cursor::new(chunk));

        for i in 0..16 {
            let mut buf = [0u8; 4];
            let mut chunk = buf_reader.by_ref().take(4);
            chunk.read(&mut buf)?;
            schedule[i] = u32::from_be_bytes(buf);
        }

        for i in 16..80 {
            let value = schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16];
            schedule[i] = value.rotate_left(1);
        }

        Ok(schedule)
    }

    fn f(&self, x: u32, y: u32, z: u32, t: usize) -> u32 {
        match t {
            0..20 => self.ch(x, y, z),
            20..40 => self.parity(x, y, z),
            40..60 => self.maj(x, y, z),
            60..80 => self.parity(x, y, z),
            _ => panic!("invalid t parameter provieded to f(): {}", t)
        }
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
    fn K(&self, t: usize) -> u32 {
        match t {
            0..20 => 0x5a827999,
            20..40 => 0x6ed9eba1,
            40..60 => 0x8f1bbcdc,
            60..80 => 0xca62c1d6,
            _ => panic!("invalid t parameter provided to K(): {}", t)
        }
    }
}

impl Display for SHA1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.digest())
    }
}


#[cfg(test)]
mod sha1_tests {
    use std::{fmt::Debug, vec};
    use super::*;

    #[test]
    fn digest_works_1() {
        let mut sha1 = SHA1::new();
        sha1.h0 = 0x01010101;
        sha1.h1 = 0x02020202;
        sha1.h2 = 0x03030303;
        sha1.h3 = 0x04040404;
        sha1.h4 = 0x05050505;
        let expected = "0101010102020202030303030404040405050505";
        assert_eq!(expected, sha1.digest());
    }

    #[test]
    fn digest_works_2() {
        let mut sha1 = SHA1::new();
        sha1.h0 = 0xaaaaaaaa;
        sha1.h1 = 0xbbbbbbbb;
        sha1.h2 = 0xcccccccc;
        sha1.h3 = 0xdddddddd;
        sha1.h4 = 0xeeeeeeee;
        let expected = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee";
        assert_eq!(expected, sha1.digest());
    }

    #[test]
    fn ingest_works_1() {
        let mut sha1 = SHA1::new();
        let mut input: Vec<u8> = vec![];
        let len = input.len();
        let _ = sha1.pad_message(&mut input, len); // TODO: don't rely on pad_message() to work
        sha1.ingest(input).expect("uh oh");
        assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1.digest());
    }

    #[test]
    fn ingest_works_2() {
        let mut sha1 = SHA1::new();
        let mut input: Vec<u8> = b"test".to_vec();
        let len = input.len();
        let _ = sha1.pad_message(&mut input, len); // TODO: don't rely on pad_message() to work
        sha1.ingest(input).expect("uh oh");
        assert_eq!("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", sha1.digest());
    }

    #[test]
    fn ingest_works_3() {
        let mut sha1 = SHA1::new();
        let mut input = b"this is a longer message to be digested that causes multiple 512-bit blocks to be processed".to_vec();
        let len = input.len();
        let _ = sha1.pad_message(&mut input, len); // TODO: don't rely on pad_message() to work
        sha1.ingest(input).expect("uh oh");
        assert_eq!("59638ef75030bf4632b9b58d2eb41e20fa2b1f61", sha1.digest());
    }

    #[test]
    fn pad_message_works_1() {
        let sha1 = SHA1::new();
        let mut input: Vec<u8> = b"abc".to_vec();
        let len = input.len();
        let expected = 64;

        let _ = sha1.pad_message(&mut input, len);
        assert_eq!(
            expected, input.len(),
            "output length of {} is incorrect, should be {}",
            input.len(), expected
        );
    }

    #[test]
    fn pad_message_works_2() {
        let sha1 = SHA1::new();
        let mut input = b"abc".to_vec();
        let mut expected = [0u8; 64];
        let len = input.len();

        expected[..3].copy_from_slice(b"abc");
        expected[3] = 0x80;
        expected[63] = 0x18;

        let _ = sha1.pad_message(&mut input, len);
        compare_arrays(&expected, &input);
    }

    #[test]
    fn pad_message_works_3() {
        let sha1 = SHA1::new();
        let msg = "this is a longer message to be digested that causes multiple 512-bit blocks to be processed";
        let mut input: Vec<u8> = msg.as_bytes().iter().copied().collect();
        let len = input.len();
        let expected = 128;
        let _ = sha1.pad_message(&mut input, len);
        assert_eq!(
            expected, input.len(),
            "output length of {} is incorrect, should be {}",
            input.len(), expected
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
        expected[126] = 0x02;
        expected[127] = 0xd8;

        let _ = sha1.pad_message(&mut message, len);
        compare_arrays(&expected, &message);
    }

    #[test]
    fn prepare_message_schedule_works_1() {
        let sha1 = SHA1::new();
        let padded_msg = [0u8; 64];
        let actual = sha1.prepare_message_schedule(padded_msg).unwrap();
        assert_eq!(actual.len(), 80);
    }

    #[test]
    fn prepare_message_schedule_works_2() {
        let sha1 = SHA1::new();

        let mut padded_msg = [0u8; 64];
        padded_msg[..3].copy_from_slice(b"abc");
        padded_msg[3] = 0x80;
        padded_msg[63] = 0x18;

        let expected: [u32; 80] = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000018,
            0xC2C4C700, 0x00000000, 0x00000030, 0x85898E01,
            0x00000000, 0x00000060, 0x0B131C03, 0x00000030,
            0x85898EC1, 0x16263806, 0x00000000, 0x00000180,
            0x2C4C700C, 0x000000F0, 0x93AFB507, 0x5898E048,
            0x8E9A9202, 0x00000600, 0xB131C0F0, 0x16263BC6,
            0x4EBED41E, 0x626380A1, 0x16263806, 0x000018C0,
            0xD2E138C4, 0x00000F00, 0x3AFB5079, 0x898E04E5,
            0xE2BA3C2B, 0x000060C0, 0x053A37CD, 0x74458547,
            0xDA9415ED, 0x26380A16, 0x626383A1, 0x4EBF54DE,
            0x3835B44B, 0x0000F600, 0x1E84C7A3, 0x98E04D98,
            0x651D16A0, 0x62658CA1, 0x458544D6, 0x44584CB7,
            0x7BA06619, 0x6380AEA2, 0x0AE55269, 0x627B49A1,
            0x7CD45C9D, 0x000F0000, 0xFB50753A, 0xEC6765E8,
            0xBA3C2BE2, 0x0060C000, 0x3A37CD05, 0x458546F4,
            0xB8599DD6, 0x380A1A26, 0x01E02203, 0xE7CC3456,
            0xE6E60B69, 0x00F60A00, 0x5795EF4F, 0x822E0879,
        ];

        let actual = sha1.prepare_message_schedule(padded_msg).unwrap();
        compare_arrays(expected.as_ref(), actual.as_ref());
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
        let sha1 = SHA1::new();
        assert_eq!(sha1.ch(1, 2, 3), sha1.f(1, 2, 3, 0));
    }

    #[test]
    fn f_works_2() {
        let sha1 = SHA1::new();
        assert_eq!(sha1.parity(1, 2, 3), sha1.f(1, 2, 3, 20));
    }

    #[test]
    fn f_works_3() {
        let sha1 = SHA1::new();
        assert_eq!(sha1.maj(1, 2, 3), sha1.f(1, 2, 3, 40));
    }

    #[test]
    fn f_works_4() {
        let sha1 = SHA1::new();
        assert_eq!(sha1.parity(1, 2, 3), sha1.f(1, 2, 3, 60));
    }

    #[test]
    #[should_panic]
    fn f_works_5() {
        let sha1 = SHA1::new();
        sha1.f(1, 2, 3, 80);
    }

    trait Unsigned {}
    impl Unsigned for u8 {}
    impl Unsigned for u32 {}

    fn compare_arrays<T>(expected: &[T], actual: &[T])
    where 
        T: Unsigned + PartialEq + Debug + Display + Clone
    {
        assert_eq!(
            expected.len(), actual.len(),
            "expected and actual arrays differ in length; {} != {}",
            expected.len(), actual.len(),
        );
        for (i, x) in actual.iter().enumerate() {
            let expected_val = &expected[i];
            assert_eq!(
                *expected_val, *x,
                "actual array is incorrect at index {} ({} != {}; expected != actual)",
                i, expected_val, *x
            );
        }
    }
}
