use std::convert::TryFrom;
use std::fs::File;
use std::str::FromStr;
use tpm_openpgp::Description;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use tss_esapi::structures::{EccParameter, EccPoint, SymmetricDefinition};
use tss_esapi::{Context, Tcti};

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

    let tcti = Tcti::from_str(&deserialized.spec.provider.tpm.tcti)?;

    let mut context = Context::new(tcti)?;

    let session = context.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::AES_256_CFB,
        HashingAlgorithm::Sha256,
    )?;
    let (session_attr, session_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(session.unwrap(), session_attr, session_mask)
        .unwrap();
    context.set_sessions((session, None, None));

    let data = {
        use std::io::Read;
        let mut public_point = File::open(opt.public_point)?;
        let mut data = vec![];
        public_point.read_to_end(&mut data)?;
        data
    };

    let size = data.len() / 2;

    let key_handle = tpm_openpgp::convert_to_key_handle(&mut context, &deserialized.spec)?;

    let z_point = context.ecdh_z_gen(
        key_handle,
        EccPoint::new(
            EccParameter::try_from(&data[..size])?,
            EccParameter::try_from(&data[size..])?,
        ),
    )?;

    use std::io::Write;

    let mut stdout = std::io::stdout();
    stdout.write_all(z_point.x().value())?;

    Ok(())
}
