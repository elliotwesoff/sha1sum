use std::num::TryFromIntError;
use crate::errors::PaddingError;
use std::fmt::Display;

pub trait SHA: Display {
    fn digest(&mut self, input_stream: &[u8]) -> Result<(), PaddingError> {
        let chunks = input_stream.chunks(64);

        for chunk in chunks {
            self.digest_chunk(chunk)?
        }

        Ok(())
    }

    fn digest_chunk(&mut self, chunk: &[u8]) -> Result<(), PaddingError>;

    fn pad_message(&self, message: &mut Vec<u8>, total_size: usize) -> Result<(), TryFromIntError> {
        // TODO: can this be made private but also "inherited" to this trait's
        //       implementers? composition? need to figure out how to determine
        //       if the current chunk is the last chunk of the message.
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
}