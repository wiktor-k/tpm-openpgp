use std::convert::TryInto;
use std::fs::File;
use std::str::FromStr;
use tpm_openpgp::{Description, EcPublic, RsaPublic};
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::constants::PropertyTag;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use tss_esapi::structures::SymmetricDefinition;
use tss_esapi::utils::PublicIdUnion;
use tss_esapi::{Context, Tcti};

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

    let manu = context.get_tpm_property(PropertyTag::Manufacturer)?;
    let name = hex::encode(context.tr_get_name(key_handle.into())?.value());

    let (public, _, _) = context.read_public(key_handle)?;

    let public_key = match unsafe { PublicIdUnion::from_public(&public)? } {
        // call should be safe given our trust in the TSS library
        PublicIdUnion::Rsa(pub_key) => {
            let mut key = pub_key.buffer.to_vec();
            key.truncate(pub_key.size.try_into().unwrap()); // should not fail on supported targets
                                                            //eprintln!("key = {:#?}", key);
            tpm_openpgp::PublicKeyBytes::RSA(RsaPublic {
                bytes: hex::encode(key),
            })
        }
        PublicIdUnion::Ecc(pub_key) => {
            let mut x = pub_key.x.buffer.to_vec();
            x.truncate(pub_key.x.size.try_into().unwrap()); // should not fail on supported targets
            let mut y = pub_key.y.buffer.to_vec();
            y.truncate(pub_key.y.size.try_into().unwrap()); // should not fail on supported targets
            tpm_openpgp::PublicKeyBytes::EC(EcPublic {
                x: hex::encode(x),
                y: hex::encode(y),
            })
        }
        _ => panic!("Unsupported key type."),
    };

    let value = tpm_openpgp::Status {
        public_key,
        manu,
        name,
    };
    println!("{}", serde_yaml::to_string(&value)?);

    Ok(())
}
