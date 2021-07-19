use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::str::FromStr;
use tpm_openpgp::Description;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::handles::PersistentTpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::structures::{Auth, SymmetricDefinition};
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

    let (session_attr, session_mask) = SessionAttributesBuilder::new().build();
    context.tr_sess_set_attributes(session.unwrap(), session_attr, session_mask)?;
    context.set_sessions((session, None, None));

    let key_auth = { Auth::try_from(deserialized.spec.auth.as_bytes())? };
    let pk = context.create_primary(
        Hierarchy::Owner,
        &tpm_openpgp::create(&deserialized.spec)?,
        Some(&key_auth),
        None,
        None,
        None,
    )?;

    println!("Generated key handle = 0x{:X}", pk.key_handle.value());

    let persistent = Persistent::Persistent(PersistentTpmHandle::new(
        deserialized.spec.provider.tpm.handle,
    )?);

    context.evict_control(Provision::Owner, pk.key_handle.into(), persistent)?;

    let (public, _, _) = context.read_public(pk.key_handle)?;

    match unsafe { PublicIdUnion::from_public(&public)? } {
        // call should be safe given our trust in the TSS library
        PublicIdUnion::Rsa(pub_key) => {
            let mut key = pub_key.buffer.to_vec();
            key.truncate(pub_key.size.try_into().unwrap()); // should not fail on supported targets
            eprintln!("key = {:#?}", key);
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
    println!("Key persisted. Check `tpm2_getcap handles-persistent`.");
    /*println!(
        "To remove the key from the TPM use `tpm2_evictcontrol -c 0x{:X}`.",
        opt.handle
    );*/

    eprintln!("Out = {:#?}", pk.key_handle.value());
    Ok(())
}
