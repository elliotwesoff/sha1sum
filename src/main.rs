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

fn read_chunk<T>(stream: &mut T) -> Result<Vec<u8>, Box<dyn Error>>
where
    T: Read
{
    let mut v: Vec<u8> = vec![0u8; BUFSIZE];
    let limit: u64 = BUFSIZE.try_into().unwrap();
    let bytes_read = stream.take(limit).read(&mut v)?;
    v.truncate(bytes_read);
    Ok(v)
}

fn run(config: Config) -> Result<String, Box<dyn Error>> {
    let mut sha1 = SHA1::new();
    let input_reader: Box<dyn Read>;
    let mut total_bytes: usize = 0;

    input_reader = get_input_reader(config)?;
    let mut buf_input_reader = BufReader::new(input_reader);

    loop {
        let mut buf = read_chunk(buf_input_reader.by_ref())?;
        total_bytes += buf.len();

        match buf.len() {
            BUFSIZE => sha1.ingest(buf)?,
            0 => break,
            _ => {
                sha1.pad_message(&mut buf, total_bytes);
                sha1.ingest(buf)?;
            }
        }
    }

    Ok(sha1.digest())
}

fn main() {
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        println!("Error parsing arguments: {err}");
        process::exit(1);
    });

    match run(config) {
        Ok(hash) => println!("{hash}"),
        Err(e) => eprintln!("{e}")
    }
}
