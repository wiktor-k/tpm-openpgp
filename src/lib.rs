use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use tss_esapi::attributes::object::ObjectAttributesBuilder;
use tss_esapi::constants::tss::*;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{
    EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::SymmetricDefinitionObject;
use tss_esapi::structures::{
    Auth, EccParameter, EccScheme, KeyDerivationFunctionScheme, Private, PublicBuilder,
    PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
};
use tss_esapi::structures::{EccPoint, PublicKeyRsa};

use tss_esapi::Context;
use tss_esapi::Result;

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
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(spec.private.is_none())
        .with_fixed_parent(spec.private.is_none())
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(spec.capabilities.contains(&Capability::Decrypt))
        .with_sign_encrypt(spec.capabilities.contains(&Capability::Sign))
        .with_restricted(spec.capabilities.contains(&Capability::Restrict))
        .build()?;

    let mut builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes);

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
                    rsa_params_builder.with_symmetric(SymmetricDefinitionObject::AES_128_CFB);
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
                ecc_builder = ecc_builder.with_symmetric(SymmetricDefinitionObject::AES_128_CFB);
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
