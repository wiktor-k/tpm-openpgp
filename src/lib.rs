use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use tss_esapi::abstraction::cipher::Cipher;
use tss_esapi::attributes::object::ObjectAttributesBuilder;
use tss_esapi::constants::tss::*;
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::SymmetricDefinitionObject;
use tss_esapi::structures::{Auth, Private};
use tss_esapi::tss2_esys::TPM2B_PUBLIC;
use tss_esapi::utils::Tpm2BPublicBuilder;
use tss_esapi::utils::{
    AsymSchemeUnion, PublicIdUnion, PublicParmsUnion, TpmsEccParmsBuilder, TpmsRsaParmsBuilder,
};
use tss_esapi::Context;
use tss_esapi::Result;
use tss_esapi_sys::*;

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

impl From<&PrivateRsaKeyMaterial> for TPM2B_PRIVATE_KEY_RSA {
    fn from(private_rsa: &PrivateRsaKeyMaterial) -> Self {
        let key_prime = hex::decode(&private_rsa.prime).unwrap();
        let mut key_prime_buffer = [0u8; 256];
        key_prime_buffer[..key_prime.len()].clone_from_slice(&key_prime[..key_prime.len()]);
        let key_prime_len = key_prime.len().try_into().unwrap();

        TPM2B_PRIVATE_KEY_RSA {
            size: key_prime_len,
            buffer: key_prime_buffer,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EcParameter {
    pub parameter: String,
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
pub struct Status {
    pub public_key: PublicKeyBytes,
    pub manu: Option<u32>,
    pub name: String,
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

impl From<&RsaPublic> for PublicIdUnion {
    fn from(public: &RsaPublic) -> Self {
        let public_modulus = hex::decode(&public.bytes).unwrap();
        let mut public_modulus_buffer = [0_u8; 512];
        public_modulus_buffer[..public_modulus.len()]
            .clone_from_slice(&public_modulus[..public_modulus.len()]);

        let pub_buffer = TPM2B_PUBLIC_KEY_RSA {
            size: public_modulus.len() as u16,
            buffer: public_modulus_buffer,
        };
        PublicIdUnion::Rsa(Box::from(pub_buffer))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EcPublic {
    pub x: String,
    pub y: String,
}

impl From<&EcPublic> for PublicIdUnion {
    fn from(public: &EcPublic) -> Self {
        let x = hex::decode(&public.x).unwrap();
        let y = hex::decode(&public.y).unwrap();
        let mut x_buffer = [0_u8; 128];
        x_buffer[0..x.len()].clone_from_slice(&x[..x.len()]);
        let mut y_buffer = [0_u8; 128];
        y_buffer[0..y.len()].clone_from_slice(&y[..y.len()]);

        let pub_buffer = TPMS_ECC_POINT {
            x: TPM2B_ECC_PARAMETER {
                size: x.len() as u16,
                buffer: x_buffer,
            },
            y: TPM2B_ECC_PARAMETER {
                size: y.len() as u16,
                buffer: y_buffer,
            },
        };
        PublicIdUnion::Ecc(Box::from(pub_buffer))
    }
}

impl From<&PublicKeyBytes> for PublicIdUnion {
    fn from(bytes: &PublicKeyBytes) -> Self {
        match bytes {
            PublicKeyBytes::RSA(public) => public.into(),
            PublicKeyBytes::EC(public) => public.into(),
        }
    }
}

pub fn create(spec: &Specification) -> Result<(TPM2B_PUBLIC, Option<TPM2B_SENSITIVE>)> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(spec.private.is_none())
        .with_fixed_parent(spec.private.is_none())
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(spec.capabilities.contains(&Capability::Decrypt))
        .with_sign_encrypt(spec.capabilities.contains(&Capability::Sign))
        .with_restricted(spec.capabilities.contains(&Capability::Restrict))
        .build()?;

    let mut builder = Tpm2BPublicBuilder::new()
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(attributes);

    if let Some(unique) = &spec.provider.tpm.unique {
        builder = builder.with_unique(unique.into());
    }

    builder = match &spec.algo {
        AlgorithmSpec::Rsa { bits, exponent } => {
            let rsa_params_builder = TpmsRsaParmsBuilder {
                symmetric: if spec.capabilities.contains(&Capability::Restrict) {
                    Some(SymmetricDefinitionObject::try_from(Cipher::aes_256_cfb())?.into())
                } else {
                    None
                },
                scheme: if spec.capabilities.contains(&Capability::Decrypt) {
                    Some(AsymSchemeUnion::AnySig(None))
                } else if spec.capabilities.contains(&Capability::Sign) {
                    Some(AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256))
                } else {
                    panic!("Key needs to be for decryption or for signing")
                },
                key_bits: *bits,
                exponent: exponent.unwrap_or(0),
                for_signing: spec.capabilities.contains(&Capability::Sign),
                for_decryption: spec.capabilities.contains(&Capability::Decrypt),
                restricted: spec.capabilities.contains(&Capability::Restrict),
            };

            let rsa_params = rsa_params_builder.build()?;

            builder = builder
                .with_type(TPM2_ALG_RSA)
                .with_parms(PublicParmsUnion::RsaDetail(rsa_params));

            builder
        }
        AlgorithmSpec::Ec { ref curve } => {
            let ecc_builder = TpmsEccParmsBuilder {
                symmetric: if spec.capabilities.contains(&Capability::Restrict) {
                    Some(Cipher::aes_256_cfb())
                } else {
                    None
                },
                scheme: if spec.capabilities.contains(&Capability::Decrypt) {
                    AsymSchemeUnion::AnySig(None)
                } else if spec.capabilities.contains(&Capability::Sign) {
                    AsymSchemeUnion::ECDSA(HashingAlgorithm::Sha256)
                } else {
                    panic!("Key needs to be for decryption or for signing")
                },
                curve: curve.into(),
                for_signing: spec.capabilities.contains(&Capability::Sign),
                for_decryption: spec.capabilities.contains(&Capability::Decrypt),
                restricted: spec.capabilities.contains(&Capability::Restrict),
            };
            builder = builder
                .with_type(TPM2_ALG_ECC)
                .with_parms(PublicParmsUnion::EccDetail(ecc_builder.build()?));

            builder
        }
    };

    let private = match spec.private {
        Some(PrivateKeyMaterial::Rsa(ref private_rsa)) => {
            let rsa: TPM2B_PRIVATE_KEY_RSA = private_rsa.into();

            Some((
                TPM2B_SENSITIVE {
                    size: rsa.size,
                    sensitiveArea: TPMT_SENSITIVE {
                        sensitiveType: TPM2_ALG_RSA,
                        authValue: Default::default(),
                        seedValue: Default::default(),
                        sensitive: TPMU_SENSITIVE_COMPOSITE { rsa },
                    },
                },
                (&(private_rsa.modulus)).into(),
            ))
        }
        /*	Some(PrivateKeyMaterial::Ec(ref param)) => {
            let parameter = hex::decode(&param.parameter).unwrap();
            let mut parameter_buffer = [0u8; 128];
            parameter_buffer[..parameter.len()].clone_from_slice(&parameter);
                Some((
                    TPM2B_SENSITIVE {
                        size: parameter.len() as u16,
                        sensitiveArea: TPMT_SENSITIVE {
                            sensitiveType: TPM2_ALG_ECC,
                            authValue: Default::default(),
                            seedValue: Default::default(),
                            sensitive: TPMU_SENSITIVE_COMPOSITE {
                                ecc: TPM2B_ECC_PARAMETER {
                                    size: parameter.len() as u16,
                                    buffer: parameter_buffer,
                                },
                            },
                        },
                    },
                    PublicIdUnion::Rsa(Box::from(pub_buffer)),
                ))
        },*/
        _ => None,
    };

    if let Some((sensitive, public)) = private {
        Ok((builder.with_unique(public).build()?, Some(sensitive)))
    } else {
        Ok((builder.build()?, None))
    }
}

pub fn convert_to_key_handle(
    context: &mut Context,
    specification: &Specification,
) -> Result<KeyHandle> {
    let key_handle = if let (public, Some(private)) = &create(specification)? {
        context.load_external(private, public, Hierarchy::Null)?
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
            create(specification)?.0,
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
