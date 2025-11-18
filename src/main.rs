use std::{error::Error, io::{self, Read}, process};

use sha1sum::SHA1;

const BUFSIZE: usize = 8192;

struct Config {
    file_path: String,
    stdin_provided: bool
}

impl Config {
    pub fn build(
        mut args: impl Iterator<Item = String>
    ) -> Result<Config, &'static str> {
        args.next();

        let file_path = match args.next() {
            Some(arg) => arg,
            None => return Err("Didn't get a file path"),
        };

        let stdin_provided = true;

        Ok(Config { file_path, stdin_provided })
    }
}

fn read_chunk<T>(mut chunk: T) -> Result<([u8; BUFSIZE], usize), Box<dyn Error>>
where
    T: Read
{
    let mut buf = [0u8; BUFSIZE];
    let bytes_read = chunk.read(&mut buf)?;
    Ok((buf, bytes_read))
}

fn run(config: Config) {
    let mut sha1 = SHA1::new();
    let mut n = BUFSIZE;
    let mut stdin_guard = io::stdin().lock();
    let mut errors: Vec<String> = vec![];

    while n == BUFSIZE {
        let chunk = stdin_guard.by_ref().take(BUFSIZE.try_into().unwrap());

        let (buf, bytes_read) = read_chunk(chunk).unwrap_or_else(|err| {
            sha1.set_error();
            errors.push(format!("read error: {}", err));
            ([0u8; BUFSIZE], 0)
        });

        if bytes_read == 0 {
            break;
        }

        n = bytes_read;

        sha1.ingest(buf.to_vec(), false).unwrap_or_else(|err| {
            errors.push(format!("processing error: {}", err));
        });
    }


    if errors.len() == 0 {
        println!("{}", sha1.digest());
    } else {
        for err in errors.into_iter() {
            eprintln!("{}", err);
        }
        process::exit(1);
    }
}

fn main() {
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        println!("Error parsing arguments: {err}");
        process::exit(1);
    });

    run(config)
}
