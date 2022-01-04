use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use tss_esapi::attributes::object::ObjectAttributesBuilder;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::constants::tss::*;
use tss_esapi::constants::CommandCode;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{
    EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::SymmetricDefinitionObject;
use tss_esapi::structures::{
    Auth, Digest, EccParameter, EccScheme, KeyDerivationFunctionScheme, Private, PublicBuilder,
    PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme, Signature,
    SignatureScheme,
};
use tss_esapi::Result;

use tss_esapi::constants::tss::TPM2_ST_HASHCHECK;
use tss_esapi::structures::{
    Data, EccPoint, Public, PublicKeyRsa, RsaDecryptionScheme, SymmetricDefinition,
};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::{Context, Tcti};

#[derive(Debug, Serialize, Deserialize)]
pub struct Description {
    pub spec: Specification,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Specification {
    pub provider: Provider,
    pub algo: AlgorithmSpec,
    pub private: Option<PrivateKeyMaterial>,
    pub capabilities: Vec<Capability>,
    pub auth: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateKeyMaterial {
    Rsa(PrivateRsaKeyMaterial),
    Ec(EcParameter),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateRsaKeyMaterial {
    pub prime: String,
    pub modulus: RsaPublic,
}

impl From<&PrivateRsaKeyMaterial> for tss_esapi_sys::TPM2B_PRIVATE_KEY_RSA {
    fn from(private_rsa: &PrivateRsaKeyMaterial) -> Self {
        let key_prime = hex::decode(&private_rsa.prime).unwrap();
        let mut key_prime_buffer = [0u8; 256];
        key_prime_buffer[..key_prime.len()].clone_from_slice(&key_prime[..key_prime.len()]);
        let key_prime_len = key_prime.len().try_into().unwrap();

        Self {
            size: key_prime_len,
            buffer: key_prime_buffer,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EcParameter {
    pub parameter: String,
    pub points: EcPublic,
}

impl From<&EcParameter> for tss_esapi_sys::TPM2B_ECC_PARAMETER {
    fn from(param: &EcParameter) -> Self {
        let parameter = hex::decode(&param.parameter).unwrap();
        let mut parameter_buffer = [0u8; 128];
        parameter_buffer[..parameter.len()].clone_from_slice(&parameter);
        Self {
            size: parameter.len() as u16,
            buffer: parameter_buffer,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Decrypt,
    Sign,
    Restrict,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AlgorithmSpec {
    #[serde(rename = "RSA")]
    Rsa { bits: u16, exponent: Option<u32> },
    #[serde(rename = "EC")]
    Ec { curve: EcCurve },
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum EcCurve {
    #[serde(rename = "NIST-P256")]
    NistP256,
    #[serde(rename = "NIST-P384")]
    NistP384,
}

impl From<&EcCurve> for EccCurve {
    fn from(curve: &EcCurve) -> Self {
        match curve {
            EcCurve::NistP256 => EccCurve::NistP256,
            EcCurve::NistP384 => EccCurve::NistP384,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Provider {
    pub tpm: TpmProvider,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TpmProvider {
    pub tcti: String,
    pub handle: Option<u32>,
    pub parent: Option<u32>,
    pub private: Option<String>,
    pub unique: Option<PublicKeyBytes>,
    pub wrapped: Option<WrappedKey>,
    pub policy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    pub secret: String,
    pub private: String,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PublicKeyBytes {
    RSA(RsaPublic),
    EC(EcPublic),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RsaPublic {
    pub bytes: String,
}

impl From<&RsaPublic> for PublicKeyRsa {
    fn from(public: &RsaPublic) -> Self {
        let public_modulus = hex::decode(&public.bytes).unwrap();
        PublicKeyRsa::try_from(public_modulus).unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EcPublic {
    pub x: String,
    pub y: String,
}

impl From<&EcPublic> for EccPoint {
    fn from(public: &EcPublic) -> Self {
        let x = hex::decode(&public.x).unwrap();
        let y = hex::decode(&public.y).unwrap();

        EccPoint::new(
            EccParameter::try_from(x).unwrap(),
            EccParameter::try_from(y).unwrap(),
        )
    }
}

pub fn create(
    spec: &Specification,
) -> Result<(PublicBuilder, Option<tss_esapi_sys::TPM2B_SENSITIVE>)> {
    let is_fixed = spec.private.is_none()
        && spec.provider.tpm.wrapped.is_none()
        && spec.provider.tpm.policy.is_none();
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(is_fixed)
        .with_fixed_parent(is_fixed)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(spec.capabilities.contains(&Capability::Decrypt))
        .with_sign_encrypt(spec.capabilities.contains(&Capability::Sign))
        .with_restricted(spec.capabilities.contains(&Capability::Restrict))
        .build()?;

    let mut builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes);

    if let Some(policy) = &spec.provider.tpm.policy {
        builder = builder.with_auth_policy(&Digest::try_from(hex::decode(policy).unwrap())?);
    }

    if let Some(unique) = &spec.provider.tpm.unique {
        builder = match unique {
            PublicKeyBytes::RSA(ref bytes) => builder.with_rsa_unique_identifier(&bytes.into()),
            PublicKeyBytes::EC(ref bytes) => builder.with_ecc_unique_identifier(&bytes.into()),
        }
    } else {
        builder = builder
            .with_rsa_unique_identifier(&Default::default())
            .with_ecc_unique_identifier(&Default::default());
    }

    builder = match &spec.algo {
        AlgorithmSpec::Rsa { bits, exponent } => {
            let mut rsa_params_builder = PublicRsaParametersBuilder::new();
            if spec.capabilities.contains(&Capability::Restrict) {
                rsa_params_builder =
                    rsa_params_builder.with_symmetric(SymmetricDefinitionObject::AES_256_CFB);
            }
            rsa_params_builder = rsa_params_builder
                .with_scheme(if spec.capabilities.contains(&Capability::Decrypt) {
                    RsaScheme::Null
                } else if spec.capabilities.contains(&Capability::Sign) {
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .unwrap()
                } else {
                    panic!("Key needs to be for decryption or for signing")
                })
                .with_key_bits(RsaKeyBits::try_from(*bits).unwrap())
                .with_exponent(RsaExponent::try_from(exponent.unwrap_or(0)).unwrap())
                .with_is_signing_key(spec.capabilities.contains(&Capability::Sign))
                .with_is_decryption_key(spec.capabilities.contains(&Capability::Decrypt))
                .with_restricted(spec.capabilities.contains(&Capability::Restrict));

            let rsa_params = rsa_params_builder.build()?;

            builder
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_rsa_parameters(rsa_params)
        }
        AlgorithmSpec::Ec { ref curve } => {
            let mut ecc_builder = PublicEccParametersBuilder::new()
                .with_ecc_scheme(if spec.capabilities.contains(&Capability::Decrypt) {
                    EccScheme::Null
                } else if spec.capabilities.contains(&Capability::Sign) {
                    EccScheme::create(
                        EccSchemeAlgorithm::EcDsa,
                        Some(HashingAlgorithm::Sha256),
                        None,
                    )
                    .unwrap()
                } else {
                    panic!("Key needs to be for decryption or for signing")
                })
                .with_curve(curve.into())
                .with_is_signing_key(spec.capabilities.contains(&Capability::Sign))
                .with_is_decryption_key(spec.capabilities.contains(&Capability::Decrypt))
                .with_restricted(spec.capabilities.contains(&Capability::Restrict))
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null);
            if spec.capabilities.contains(&Capability::Restrict) {
                ecc_builder = ecc_builder.with_symmetric(SymmetricDefinitionObject::AES_256_CFB);
            }

            builder = builder
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_ecc_parameters(ecc_builder.build()?);

            builder
        }
    };

    let private = match spec.private {
        Some(PrivateKeyMaterial::Rsa(ref private_rsa)) => {
            let rsa: tss_esapi_sys::TPM2B_PRIVATE_KEY_RSA = private_rsa.into();

            builder = builder.with_rsa_unique_identifier(&(&private_rsa.modulus).into());
            Some(tss_esapi_sys::TPM2B_SENSITIVE {
                size: rsa.size,
                sensitiveArea: tss_esapi_sys::TPMT_SENSITIVE {
                    sensitiveType: TPM2_ALG_RSA,
                    authValue: Default::default(),
                    seedValue: Default::default(),
                    sensitive: tss_esapi_sys::TPMU_SENSITIVE_COMPOSITE { rsa },
                },
            })
        }
        Some(PrivateKeyMaterial::Ec(ref param)) => {
            let ecc: tss_esapi_sys::TPM2B_ECC_PARAMETER = param.into();
            builder = builder.with_ecc_unique_identifier(&(&(param.points)).into());
            Some(tss_esapi_sys::TPM2B_SENSITIVE {
                size: ecc.size,
                sensitiveArea: tss_esapi_sys::TPMT_SENSITIVE {
                    sensitiveType: TPM2_ALG_ECC,
                    authValue: Default::default(),
                    seedValue: Default::default(),
                    sensitive: tss_esapi_sys::TPMU_SENSITIVE_COMPOSITE { ecc },
                },
            })
        }
        _ => None,
    };

    Ok((builder, private))
}

pub fn convert_to_key_handle(
    context: &mut Context,
    specification: &Specification,
) -> Result<KeyHandle> {
    let key_handle = if let (public, Some(private)) = create(specification)? {
        context.load_external(&private, &public.build()?, Hierarchy::Null)?
    } else if let Some(handle) = specification.provider.tpm.handle {
        let persistent_tpm_handle = PersistentTpmHandle::new(handle)?;

        let handle = context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                .expect("Need handle")
        });

        handle.into()
    } else if let (Some(parent), Some(private)) = (
        specification.provider.tpm.parent,
        &specification.provider.tpm.private,
    ) {
        let persistent_tpm_handle = PersistentTpmHandle::new(parent)?;

        let handle = context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                .expect("Need handle")
        });

        let key_handle: KeyHandle = handle.into();

        context.tr_set_auth(
            key_handle.into(),
            &Auth::try_from(specification.auth.as_bytes())?,
        )?;

        context.load(
            key_handle,
            Private::try_from(hex::decode(private).unwrap())?,
            &create(specification)?.0.build()?,
        )?
    } else {
        panic!("Cannot load key");
    };

    context.tr_set_auth(
        key_handle.into(),
        &Auth::try_from(specification.auth.as_bytes())?,
    )?;

    Ok(key_handle)
}

pub fn read_key(spec: &mut Specification) -> Result<()> {
    let tcti = Tcti::from_str(&spec.provider.tpm.tcti)?;

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

    let key_handle = convert_to_key_handle(&mut context, spec)?;

    let (public, _, _) = context.read_public(key_handle)?;

    let public_key = match &public {
        Public::Rsa { unique, .. } => PublicKeyBytes::RSA(RsaPublic {
            bytes: hex::encode(unique.value()),
        }),
        Public::Ecc { unique, .. } => PublicKeyBytes::EC(EcPublic {
            x: hex::encode(unique.x().value()),
            y: hex::encode(unique.y().value()),
        }),
        _ => panic!("Unsupported key type."),
    };

    spec.provider.tpm.unique = Some(public_key);
    spec.provider.tpm.policy = hex::encode(
        match &public {
            tss_esapi::structures::Public::Rsa { auth_policy, .. } => auth_policy,
            tss_esapi::structures::Public::Ecc { auth_policy, .. } => auth_policy,
            _ => panic!("Unsupported key type."),
        }
        .value(),
    )
    .into();

    Ok(())
}

pub fn decrypt(spec: &Specification, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let tcti = Tcti::from_str(&spec.provider.tpm.tcti)?;

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

    let key_handle = convert_to_key_handle(&mut context, spec)?;

    let cipher_text = PublicKeyRsa::try_from(ciphertext)?;

    let plain_text = context.rsa_decrypt(
        key_handle,
        cipher_text,
        RsaDecryptionScheme::Null,
        Data::default(),
    )?;

    Ok(plain_text.to_vec())
}

pub fn sign(spec: &Specification, hash: &[u8]) -> Result<Vec<u8>> {
    let tcti = Tcti::from_str(&spec.provider.tpm.tcti)?;

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

    let key_handle = convert_to_key_handle(&mut context, spec)?;

    let scheme = SignatureScheme::Null;
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    }
    .try_into()?;

    let digest = &Digest::try_from(hash)?;

    let signature = context.sign(key_handle, digest, scheme, validation)?;

    Ok(match signature {
        Signature::RsaSsa(ref signature) => Vec::from(signature.signature().value()),
        Signature::EcDsa(signature) => {
            let mut sig = vec![];
            sig.extend(signature.signature_r().value());
            sig.extend(signature.signature_s().value());
            sig
        }
        _ => panic!("Unsupported signature scheme."),
    })
}

pub fn wrap(spec: &mut Specification, parent: &Specification) -> Result<()> {
    let tcti = Tcti::from_str(&spec.provider.tpm.tcti)?;

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

    context.policy_command_code(policy_session, CommandCode::Duplicate)?;
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

    let key_handle = if let (public, Some(private)) = create(spec)? {
        context.load_external(
            &private,
            &public.with_auth_policy(&digest).build()?,
            Hierarchy::Null,
        )?
    } else {
        panic!("Can import only private keys");
    };

    let parent_handle =
        context.load_external_public(&create(parent)?.0.build()?, Hierarchy::Null)?;

    let (public, _, _) = context.read_public(key_handle)?;

    let public_key = match &public {
        Public::Rsa { unique, .. } => PublicKeyBytes::RSA(RsaPublic {
            bytes: hex::encode(unique.value()),
        }),
        Public::Ecc { unique, .. } => PublicKeyBytes::EC(EcPublic {
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

    spec.provider.tpm.unique = Some(public_key);
    spec.private = None;

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

    context.policy_command_code(policy_session, CommandCode::Duplicate)?;
    context.set_sessions((Some(policy_auth_session), None, None));

    let (data, private, secret) = context.duplicate(
        key_handle.into(),
        parent_handle.into(),
        None,
        SymmetricDefinitionObject::Null,
    )?;

    spec.provider.tpm.wrapped = Some(WrappedKey {
        private: hex::encode(private.value()),
        secret: hex::encode(secret.value()),
        data: hex::encode(data.value()),
    });
    spec.provider.tpm.policy = Some(hex::encode(auth_policy));
    spec.provider.tpm.parent = parent.provider.tpm.handle;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
