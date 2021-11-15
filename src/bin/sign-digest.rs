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

    let mut hash = vec![0; 32];
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle.read_exact(&mut hash)?;

    let signature = tpm_openpgp::sign(&deserialized.spec, &hash)?;

    let mut stdout = std::io::stdout();
    stdout.write_all(&signature)?;

    Ok(())
}
