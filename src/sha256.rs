use std::fmt::{Display, Formatter};
use crate::errors::PaddingError;
use crate::sha::SHA;


pub struct SHA256 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32
}

impl SHA256 {
    pub fn new() -> Self {
        SHA256 {
            h0: 0x6a09e667,
            h1: 0xbb67ae85,
            h2: 0x3c6ef372,
            h3: 0xa54ff53a,
            h4: 0x510e527f,
            h5: 0x9b05688c,
            h6: 0x1f83d9ab,
            h7: 0x5be0cd19
        }
    }
}

impl SHA for SHA256 {
    fn digest_chunk(&mut self, chunk: &[u8]) -> Result<(), PaddingError> {
        todo!()
    }
}

impl Display for SHA256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.h0, self.h1, self.h2, self.h3,
            self.h4, self.h5, self.h6, self.h7,
        )
    }
}