use std::{error::Error, fs, io::{self, BufReader, Read, StdinLock}, process};
use std::fs::File;
use sha1sum::{SHA1, SHA256};
use sha1sum::sha::SHA;

const BUFSIZE: usize = 8192;

struct Config {
    alg: String,
    file_path: Option<String>,
}

impl Config {
    pub fn build(
        mut args: impl Iterator<Item = String>
    ) -> Result<Config, &'static str> {
        args.next();
        let alg = args.next().ok_or("No algorithm provided")?;
        let file_path = args.next();
        Ok(Config { alg, file_path })
    }
}

enum StreamSource<'a> {
    File(File),
    Stdin(StdinLock<'a>)
}

impl Read for StreamSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            StreamSource::File(file) => file.read(buf),
            StreamSource::Stdin(stdin_lock) => stdin_lock.read(buf),
        }
    }
}

fn run<T>(sha: &mut dyn SHA, mut reader: T) -> Result<String, Box<dyn Error>> // TODO: better result error type
where
    T: Read
{
    let mut total_bytes: usize = 0;

    loop {
        let mut buf: Vec<u8> = vec![];

        total_bytes += reader.by_ref()
                             .take(BUFSIZE as u64)
                             .read_to_end(&mut buf)?;

        match buf.len() {
            BUFSIZE => sha.digest(&buf)?,
            _ => {
                sha.pad_message(&mut buf, total_bytes)?;
                sha.digest(&buf)?;
                break
            }
        }
    }

    Ok(sha.to_string())
}

fn main() {
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        eprintln!("Error parsing arguments: {err}");
        process::exit(1);
    });

    let mut sha: Box<dyn SHA> = match config.alg.as_str() {
        "1" => Box::new(SHA1::new()),
        "256" => Box::new(SHA256::new()),
        _ => {
            eprintln!("Invalid algorithm provided: {0}", config.alg);
            process::exit(1);
        }
    };

    let input_reader = match config.file_path {
        Some(file_path) => {
            let file_handle = fs::File::open(&file_path).unwrap_or_else(|err| {
                println!("Cannot open file {}: {:?}", file_path, err);
                process::exit(1);
            });
            StreamSource::File(file_handle)
        },
        None => {
            StreamSource::Stdin(io::stdin().lock())
        }
    };

    let buf_input_reader = BufReader::new(input_reader);

    match run(&mut *sha, buf_input_reader) {
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
        let mut sha = Box::new(SHA1::new());
        let reader = Cursor::new(b"hello");
        let output = run(&mut *sha, reader).unwrap();
        assert_eq!("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", output);
    }
}
