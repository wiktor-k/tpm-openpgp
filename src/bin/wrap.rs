use std::fs::File;

use tpm_openpgp::Description;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,

    #[structopt(short, long)]
    parent: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let opt = Opt::from_args();

    let parent: Description = serde_yaml::from_reader(File::open(opt.parent)?)?;

    let mut deserialized: Description = serde_yaml::from_reader(File::open(opt.file)?)?;

    tpm_openpgp::wrap(&mut deserialized.spec, &parent.spec)?;

    println!("{}", serde_yaml::to_string(&deserialized)?);

    Ok(())
}
