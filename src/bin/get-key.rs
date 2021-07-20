use std::convert::TryInto;
use std::fs::File;
use std::str::FromStr;
use tpm_openpgp::Description;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::constants::PropertyTag;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
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
    eprintln!("In = {:#?}", deserialized);

    let tcti = Tcti::from_str(&deserialized.spec.provider.tpm.tcti)?;

    let mut context = unsafe { Context::new(tcti)? };

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

    eprintln!("2");
    //context.ev
    // println!("Vendor = {}", tss_esapi::utils::get_tpm_vendor(&mut context)?);

    // GENERATE AND PERSIST IN TPM
    let persistent_tpm_handle = PersistentTpmHandle::new(deserialized.spec.provider.tpm.handle)?;

    eprintln!("3");
    let handle = context.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
            .expect("Need handle")
    });

    eprintln!("4");

    let key_handle: KeyHandle = handle.into();

    let (public, _, _) = context.read_public(key_handle)?;

    match unsafe { PublicIdUnion::from_public(&public)? } {
        // call should be safe given our trust in the TSS library
        PublicIdUnion::Rsa(pub_key) => {
            let mut key = pub_key.buffer.to_vec();
            key.truncate(pub_key.size.try_into().unwrap()); // should not fail on supported targets
                                                            //eprintln!("key = {:#?}", key);
            let value = tpm_openpgp::Status {
                bytes: hex::encode(key),
                manu: context.get_tpm_property(PropertyTag::Manufacturer)?,
                name: hex::encode(context.tr_get_name(key_handle.into())?.value()),
            };
            println!("{}", serde_yaml::to_string(&value)?);
        }
        PublicIdUnion::Ecc(pub_key) => {
            let mut x = pub_key.x.buffer.to_vec();
            x.truncate(pub_key.x.size.try_into().unwrap()); // should not fail on supported targets
            let mut y = pub_key.y.buffer.to_vec();
            y.truncate(pub_key.y.size.try_into().unwrap()); // should not fail on supported targets
            eprintln!("x = {:#?}, y = ${:#?}", x, y);
        }
        _ => panic!("O_O"),
    };
    //println!("Key persisted. Check `tpm2_getcap handles-persistent`.");
    /*println!(
        "To remove the key from the TPM use `tpm2_evictcontrol -c 0x{:X}`.",
        opt.handle
    );*/

    //eprintln!("Out = {:#?}", pk.key_handle.value());
    Ok(())
}
