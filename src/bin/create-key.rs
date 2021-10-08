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
use tss_esapi::structures::{
    Auth, Data, EncryptedSecret, Private, Public, SymmetricDefinition, SymmetricDefinitionObject,
};

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
    context.tr_sess_set_attributes(session.unwrap(), session_attr, session_mask)?;
    context.set_sessions((session, None, None));

    let key_auth = { Auth::try_from(deserialized.spec.auth.as_bytes())? };
    if let Some(handle) = deserialized.spec.provider.tpm.handle {
        let pk = context.create_primary(
            Hierarchy::Owner,
            &tpm_openpgp::create(&deserialized.spec)?.0.build()?,
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

        let public = tpm_openpgp::create(&deserialized.spec)?.0.build()?;

        let (out_private, out_public) =
            if let Some(wrapped_key) = &deserialized.spec.provider.tpm.wrapped {
                let private = Private::try_from(hex::decode(&wrapped_key.private).unwrap())?;

                let secret = EncryptedSecret::try_from(hex::decode(&wrapped_key.secret).unwrap())?;
                let data = Data::try_from(hex::decode(&wrapped_key.data).unwrap())?;

                let private = context.import(
                    key_handle.into(),
                    Some(data),
                    public.clone(),
                    private,
                    secret,
                    SymmetricDefinitionObject::Null,
                )?;

                let child_handle = context.load(key_handle, private.clone(), &public)?;
                let public = context.read_public(child_handle)?.0;
                (private, public)
            } else {
                let pk = context.create(key_handle, &public, Some(&key_auth), None, None, None)?;
                (pk.out_private, pk.out_public)
            };

        deserialized.spec.provider.tpm.private = Some(hex::encode(out_private.value()));
        deserialized.spec.provider.tpm.unique = match &out_public {
            Public::Rsa { unique, .. } => Some(PublicKeyBytes::RSA(RsaPublic {
                bytes: hex::encode(unique.value()),
            })),
            Public::Ecc { unique, .. } => Some(PublicKeyBytes::EC(EcPublic {
                x: hex::encode(unique.x().value()),
                y: hex::encode(unique.y().value()),
            })),
            _ => panic!("Unsupported public area type"),
        };
        deserialized.spec.provider.tpm.wrapped = None;

        let auth_policy = match &out_public {
            tss_esapi::structures::Public::Rsa { auth_policy, .. } => auth_policy,
            tss_esapi::structures::Public::Ecc { auth_policy, .. } => auth_policy,
            _ => panic!("Unsupported key type."),
        }
        .value();

        deserialized.spec.provider.tpm.policy = if auth_policy.is_empty() {
            None
        } else {
            hex::encode(auth_policy).into()
        };

        println!("{}", serde_yaml::to_string(&deserialized)?);
    } else {
        panic!("Unknown key definition. Aborting...");
    }
    Ok(())
}
