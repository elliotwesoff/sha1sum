use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub struct PaddingError;

impl Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "input is not padded correctly")
    }
}

impl Error for PaddingError {}
