use std::{error::Error, fs, io::{self, BufReader, Read}, process};
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

fn get_input_reader(config: Config) -> Result<Box<dyn Read>, io::Error> {
    match config.file_path {
        Some(file_path) => {
            let file_handle = fs::File::open(file_path)?;
            let boxed_handle = Box::new(file_handle);
            Ok(boxed_handle)
        },
        None => {
            let boxed_stdin = Box::new(io::stdin().lock());
            Ok(boxed_stdin)
        }
    }
}

fn read_chunk<T>(stream: &mut T, limit: u64) -> Result<Vec<u8>, Box<dyn Error>>
where
    T: Read
{
    let mut v: Vec<u8> = vec![0u8; BUFSIZE];

    // TODO: take() doesn't guarantee that any number
    // of bytes will be read. make sure the returned
    // vector is full, or if not full, EOF is reached
    // on the reader stream. (without this guarantee,
    // the input may only be partially processed when
    // run() returns).
    let bytes_read = stream.take(limit).read(&mut v)?;

    v.truncate(bytes_read);
    Ok(v)
}

fn run<T>(mut reader: T) -> Result<String, Box<dyn Error>>
where
    T: Read
{
    let mut sha1 = SHA1::new();
    let mut total_bytes: usize = 0;

    loop {
        let mut buf = read_chunk(reader.by_ref(), BUFSIZE as u64)?;
        total_bytes += buf.len();

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
