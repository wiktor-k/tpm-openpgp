use std::str::FromStr;

use tss_esapi::{Context, Tcti};

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "draw-bytes")]
struct Opt {
    // Backsignature created by the signing key.
    #[structopt(short, long, default_value = "device:/dev/tpmrm0")]
    tcti: String,

    // Public parts of the signing subkey.
    #[structopt(short, long, default_value = "32")]
    size: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let tcti = Tcti::from_str(&opt.tcti)?;
    let mut context = unsafe { Context::new(tcti)? };
    let digest = context.get_random(opt.size)?;
    let bytes: &[u8] = digest.value();
    for byte in bytes {
        print!("{:02x}", byte);
    }
    println!();
    Ok(())
}
