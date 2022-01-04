use std::fs::File;
use std::io::Read;
use std::io::Write;

use tpm_openpgp::Description;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    let deserialized: Description = serde_yaml::from_reader(File::open(opt.file)?)?;

    let mut bytes = vec![];
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle.read_to_end(&mut bytes)?;

    let plain_text = tpm_openpgp::decrypt(&deserialized.spec, &bytes)?;

    let mut stdout = std::io::stdout();
    stdout.write_all(&plain_text)?;

    Ok(())
}
