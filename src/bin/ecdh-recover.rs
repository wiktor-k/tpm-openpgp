use std::fs::File;
use tpm_openpgp::Description;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,

    #[structopt(short, long)]
    public_point: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    let deserialized: Description = serde_yaml::from_reader(File::open(opt.file)?)?;

    let data = {
        use std::io::Read;
        let mut public_point = File::open(opt.public_point)?;
        let mut data = vec![];
        public_point.read_to_end(&mut data)?;
        data
    };

    let (z_point_x, _) = tpm_openpgp::derive(&deserialized.spec, &data)?;

    use std::io::Write;

    let mut stdout = std::io::stdout();
    stdout.write_all(&z_point_x)?;

    Ok(())
}
