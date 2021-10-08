use std::fs::File;
use std::str::FromStr;
use tpm_openpgp::{Description, EcPublic, RsaPublic};
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use tss_esapi::structures::{Public, SymmetricDefinition};
use tss_esapi::{Context, Tcti};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let opt = Opt::from_args();

    let mut deserialized: Description = serde_yaml::from_reader(File::open(opt.file)?)?;

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

    let (public, _, _) = context.read_public(key_handle)?;

    let public_key = match &public {
        // call should be safe given our trust in the TSS library
        Public::Rsa { unique, .. } => tpm_openpgp::PublicKeyBytes::RSA(RsaPublic {
            bytes: hex::encode(unique.value()),
        }),
        Public::Ecc { unique, .. } => tpm_openpgp::PublicKeyBytes::EC(EcPublic {
            x: hex::encode(unique.x().value()),
            y: hex::encode(unique.y().value()),
        }),
        _ => panic!("Unsupported key type."),
    };

    deserialized.spec.provider.tpm.unique = Some(public_key);
    deserialized.spec.provider.tpm.policy = hex::encode(
        match &public {
            tss_esapi::structures::Public::Rsa { auth_policy, .. } => auth_policy,
            tss_esapi::structures::Public::Ecc { auth_policy, .. } => auth_policy,
            _ => panic!("Unsupported key type."),
        }
        .value(),
    )
    .into();

    println!("{}", serde_yaml::to_string(&deserialized)?);

    Ok(())
}
