use std::convert::TryFrom;
use std::fs::File;
use std::str::FromStr;

use tpm_openpgp::{Description, EcPublic, RsaPublic};

use structopt::StructOpt;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::constants::tss::TPM2_CC_Duplicate;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{Public, SymmetricDefinition, SymmetricDefinitionObject};
use tss_esapi::{Context, Tcti};

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,

    #[structopt(short, long)]
    parent: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let opt = Opt::from_args();

    let parent: Description = serde_yaml::from_reader(File::open(opt.parent)?)?;

    let mut deserialized: Description = serde_yaml::from_reader(File::open(opt.file)?)?;

    let tcti = Tcti::from_str(&deserialized.spec.provider.tpm.tcti)?;

    let mut context = Context::new(tcti)?;

    // create a policy digest that allows key duplication
    let trial_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?
        .expect("Start auth session returned a NONE handle");

    let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
        SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

    context.tr_sess_set_attributes(
        trial_session,
        policy_auth_session_attributes,
        policy_auth_session_attributes_mask,
    )?;

    let policy_session = PolicySession::try_from(trial_session)?;

    context.policy_auth_value(policy_session)?;

    context.policy_command_code(policy_session, TPM2_CC_Duplicate)?;
    let digest = context.policy_get_digest(policy_session)?;
    // end of: create policy digest

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

    let key_handle = if let (public, Some(private)) = tpm_openpgp::create(&deserialized.spec)? {
        context.load_external(
            &private,
            &public.with_auth_policy(&digest).build()?,
            Hierarchy::Null,
        )?
    } else {
        panic!("Can import only private keys");
    };

    let parent_handle = context.load_external_public(
        &tpm_openpgp::create(&parent.spec)?.0.build()?,
        Hierarchy::Null,
    )?;

    let (public, _, _) = context.read_public(key_handle)?;

    let public_key = match &public {
        Public::Rsa { unique, .. } => tpm_openpgp::PublicKeyBytes::RSA(RsaPublic {
            bytes: hex::encode(unique.value()),
        }),
        Public::Ecc { unique, .. } => tpm_openpgp::PublicKeyBytes::EC(EcPublic {
            x: hex::encode(unique.x().value()),
            y: hex::encode(unique.y().value()),
        }),
        _ => panic!("Unsupported key type."),
    };

    let auth_policy = match &public {
        tss_esapi::structures::Public::Rsa { auth_policy, .. } => auth_policy,
        tss_esapi::structures::Public::Ecc { auth_policy, .. } => auth_policy,
        _ => panic!("Unsupported key type."),
    }
    .value();

    deserialized.spec.provider.tpm.unique = Some(public_key);
    deserialized.spec.private = None;

    context.set_sessions((None, None, None));

    let policy_auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?
        .expect("Start auth session returned a NONE handle");
    let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
        SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
    context.tr_sess_set_attributes(
        policy_auth_session,
        policy_auth_session_attributes,
        policy_auth_session_attributes_mask,
    )?;

    let policy_session = PolicySession::try_from(policy_auth_session)?;

    context.policy_auth_value(policy_session)?;

    context.policy_command_code(policy_session, TPM2_CC_Duplicate)?;
    context.set_sessions((Some(policy_auth_session), None, None));

    let (data, private, secret) = context.duplicate(
        key_handle.into(),
        parent_handle.into(),
        None,
        SymmetricDefinitionObject::Null,
    )?;

    deserialized.spec.provider.tpm.wrapped = Some(tpm_openpgp::WrappedKey {
        private: hex::encode(private.value()),
        secret: hex::encode(secret.value()),
        data: hex::encode(data.value()),
    });
    deserialized.spec.provider.tpm.policy = Some(hex::encode(auth_policy));
    deserialized.spec.provider.tpm.parent = parent.spec.provider.tpm.handle;

    println!("{}", serde_yaml::to_string(&deserialized)?);

    Ok(())
}
