use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;
use tpm_openpgp::Description;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use tss_esapi::structures::{Data, PublicKeyRSA, SymmetricDefinition};
use tss_esapi::{Context, Tcti};

use tss_esapi::utils::AsymSchemeUnion;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,
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

    let key_handle = tpm_openpgp::convert_to_key_handle(&mut context, &deserialized.spec)?;

    let mut bytes = vec![];
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle.read_to_end(&mut bytes)?;

    let cipher_text = PublicKeyRSA::try_from(bytes)?;

    let plain_text = context.rsa_decrypt(
        key_handle,
        cipher_text,
        AsymSchemeUnion::RSAES,
        Data::default(),
    )?;

    let mut stdout = std::io::stdout();
    stdout.write_all(&plain_text)?;

    Ok(())
}
