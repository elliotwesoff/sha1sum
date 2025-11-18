use std::{error::Error, io::{self, Read}, process, fs};

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

fn read_chunk<T>(stream: T) -> Result<Vec<u8>, Box<dyn Error>>
where
    T: Read
{
    let mut v: Vec<u8> = vec![0u8; BUFSIZE];
    let mut chunk = stream.take(BUFSIZE.try_into().unwrap());
    let bytes_read = chunk.read(&mut v)?;
    v.truncate(bytes_read);
    Ok(v)
}

fn get_input_reader(config: Config) -> Result<Box<dyn Read>, io::Error> {
    match config.file_path {
        Some(file_path) => {
            let file_handle = fs::File::open(file_path)?;
            Ok(Box::new(file_handle))
        },
        None => Ok(Box::new(io::stdin().lock()))
    }
}

fn run(config: Config) -> Result<String, Box<dyn Error>> {
    let mut sha1 = SHA1::new();
    let mut reader: Box<dyn Read>;
    let mut last = false;

    reader = get_input_reader(config)?;

    while !last {
        let buf = read_chunk(reader.by_ref())?;
        last = buf.len() != BUFSIZE;
        sha1.ingest(buf, last)?;
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
