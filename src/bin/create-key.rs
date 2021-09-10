use std::convert::TryFrom;
use std::fs::File;
use std::str::FromStr;
use tpm_openpgp::Description;
use tpm_openpgp::{EcPublic, PublicKeyBytes, RsaPublic};
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::structures::{Auth, Public, SymmetricDefinition};

use tss_esapi::{Context, Tcti};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    context.tr_sess_set_attributes(session.unwrap(), session_attr, session_mask)?;
    context.set_sessions((session, None, None));

    let key_auth = { Auth::try_from(deserialized.spec.auth.as_bytes())? };
    if let Some(handle) = deserialized.spec.provider.tpm.handle {
        let pk = context.create_primary(
            Hierarchy::Owner,
            &tpm_openpgp::create(&deserialized.spec)?.0,
            Some(&key_auth),
            None,
            None,
            None,
        )?;

        println!("Generated key handle = 0x{:X}", pk.key_handle.value());

        let persistent = Persistent::Persistent(PersistentTpmHandle::new(handle)?);

        context.evict_control(Provision::Owner, pk.key_handle.into(), persistent)?;
    } else if let Some(parent) = deserialized.spec.provider.tpm.parent {
        let persistent_tpm_handle = PersistentTpmHandle::new(parent)?;

        let handle = context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                .expect("Need handle")
        });

        let key_handle: KeyHandle = handle.into();
        context.tr_set_auth(
            key_handle.into(),
            &Auth::try_from(deserialized.spec.auth.as_bytes())?,
        )?;
        let pk = context.create(
            key_handle,
            &tpm_openpgp::create(&deserialized.spec)?.0,
            Some(&key_auth),
            None,
            None,
            None,
        )?;

        deserialized.spec.provider.tpm.private = Some(hex::encode(pk.out_private.value()));
        deserialized.spec.provider.tpm.unique = match pk.out_public {
            Public::Rsa { unique, .. } => Some(PublicKeyBytes::RSA(RsaPublic {
                bytes: hex::encode(unique.value()),
            })),
            Public::Ecc { unique, .. } => Some(PublicKeyBytes::EC(EcPublic {
                x: hex::encode(unique.x().value()),
                y: hex::encode(unique.y().value()),
            })),
            _ => panic!("Unsupported public area type"),
        };
        println!("{}", serde_yaml::to_string(&deserialized)?);
    }
    Ok(())
}
