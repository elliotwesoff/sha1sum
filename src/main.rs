use std::{error::Error, fs, io::{self, BufReader, Read, StdinLock}, process};
use std::fs::File;
use sha1sum::SHA1;

const BUFSIZE: usize = 8192;

struct Config {
    file_path: Option<String>,
}

impl Config {
    pub fn build(
        mut args: impl Iterator<Item = String>
    ) -> Result<Config, &'static str> {
        args.next();
        let file_path = args.next();
        Ok(Config { file_path })
    }
}

enum Readers<'a> {
    File(File),
    Stdin(StdinLock<'a>)
}

impl Read for Readers<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Readers::File(file) => file.read(buf),
            Readers::Stdin(stdin_lock) => stdin_lock.read(buf),
        }
    }
}

fn get_input_reader<'a>(config: Config) -> Result<Readers<'a>, io::Error> {
    match config.file_path {
        Some(file_path) => {
            let file_handle = fs::File::open(file_path)?;
            Ok(Readers::File(file_handle))
        },
        None => {
            Ok(Readers::Stdin(io::stdin().lock()))
        }
    }
}

fn run<T>(mut reader: T) -> Result<String, Box<dyn Error>> // TODO: better result error type
where
    T: Read
{
    let mut sha1 = SHA1::new();
    let mut total_bytes: usize = 0;

    loop {
        let mut buf: Vec<u8> = vec![];

        total_bytes += reader.by_ref()
                             .take(BUFSIZE as u64)
                             .read_to_end(&mut buf)?;

        match buf.len() {
            BUFSIZE => sha1.digest(&buf)?,
            _ => {
                sha1.pad_message(&mut buf, total_bytes)?;
                sha1.digest(&buf)?;
                break
            }
        }
    }

    Ok(sha1.to_string())
}

fn main() {
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        println!("Error parsing arguments: {err}");
        process::exit(1);
    });

    let input_reader = get_input_reader(config).unwrap();

    match run(BufReader::new(input_reader)) {
        Ok(checksum) => println!("{checksum}"),
        Err(e) => eprintln!("{e}")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::*;

    #[test]
    fn test_run_with_hello() {
        let reader = Cursor::new(b"hello");
        let output = run(reader).unwrap();
        assert_eq!("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", output);
    }
}
