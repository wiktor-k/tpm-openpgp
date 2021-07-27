use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use tss_esapi::abstraction::cipher::Cipher;
use tss_esapi::attributes::object::ObjectAttributesBuilder;
use tss_esapi::constants::tss::*;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::SymmetricDefinitionObject;
use tss_esapi::tss2_esys::TPM2B_PUBLIC;
use tss_esapi::utils::Tpm2BPublicBuilder;
use tss_esapi::utils::{AsymSchemeUnion, PublicIdUnion, PublicParmsUnion, TpmsRsaParmsBuilder};
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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PrivateKeyMaterial {
    Rsa(PrivateRsaKeyMaterial),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrivateRsaKeyMaterial {
    pub prime: String,
    pub modulus: String,
    pub exponent: u32,
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
pub enum PK {
    RSA,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Digest {
    #[serde(rename = "SHA-256")]
    SHA256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlgorithmSpec {
    pub pk: PK,
    pub digest: Digest,
    pub bits: u16,
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
    pub unique: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub bytes: String,
    pub manu: Option<u32>,
    pub name: String,
}

pub fn create(spec: &Specification) -> Result<(TPM2B_PUBLIC, Option<TPM2B_SENSITIVE>)> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(spec.capabilities.contains(&Capability::Decrypt))
        .with_sign_encrypt(spec.capabilities.contains(&Capability::Sign))
        .with_restricted(spec.capabilities.contains(&Capability::Restrict))
        .build()?;

    let mut builder = Tpm2BPublicBuilder::new()
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(attributes);

    //if let Rsa = &spec.algo.pk {
    let mut rsa_params_builder = TpmsRsaParmsBuilder {
        symmetric: if spec.capabilities.contains(&Capability::Decrypt) {
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
        key_bits: spec.algo.bits,
        exponent: 0,
        for_signing: spec.capabilities.contains(&Capability::Sign),
        for_decryption: spec.capabilities.contains(&Capability::Decrypt),
        restricted: spec.capabilities.contains(&Capability::Restrict),
    };

    let private = if let Some(PrivateKeyMaterial::Rsa(ref private_rsa)) = spec.private {
        rsa_params_builder.exponent = private_rsa.exponent;
        let public_modulus = hex::decode(&private_rsa.modulus).unwrap();
        let mut public_modulus_buffer = [0u8; 512];
        public_modulus_buffer[..public_modulus.len()]
            .clone_from_slice(&public_modulus[..public_modulus.len()]);

        let pub_buffer = TPM2B_PUBLIC_KEY_RSA {
            size: public_modulus.len().try_into().unwrap(),
            buffer: public_modulus_buffer,
        };
        builder = builder.with_unique(PublicIdUnion::Rsa(Box::from(pub_buffer)));
        rsa_params_builder.key_bits = pub_buffer.size;

        let key_prime = hex::decode(&private_rsa.prime).unwrap();
        let mut key_prime_buffer = [0u8; 256];
        key_prime_buffer[..key_prime.len()].clone_from_slice(&key_prime[..key_prime.len()]);
        let key_prime_len = key_prime.len().try_into().unwrap();

        Some(TPM2B_SENSITIVE {
            size: key_prime_len,
            sensitiveArea: TPMT_SENSITIVE {
                sensitiveType: TPM2_ALG_RSA,
                authValue: Default::default(),
                seedValue: Default::default(),
                sensitive: TPMU_SENSITIVE_COMPOSITE {
                    rsa: TPM2B_PRIVATE_KEY_RSA {
                        size: key_prime_len,
                        buffer: key_prime_buffer,
                    },
                },
            },
        })
    } else {
        None
    };

    let rsa_params = rsa_params_builder.build()?;

    builder = builder
        .with_type(TPM2_ALG_RSA)
        .with_parms(PublicParmsUnion::RsaDetail(rsa_params));

    if let Some(unique) = &spec.provider.tpm.unique {
        let public_modulus = hex::decode(unique).unwrap();
        let mut public_modulus_buffer = [0_u8; 512];
        public_modulus_buffer[..public_modulus.len()]
            .clone_from_slice(&public_modulus[..public_modulus.len()]);

        let pub_buffer = TPM2B_PUBLIC_KEY_RSA {
            size: public_modulus.len().try_into().unwrap(),
            buffer: public_modulus_buffer,
        };
        let pub_id_union = PublicIdUnion::Rsa(Box::from(pub_buffer));

        builder = builder.with_unique(pub_id_union);
    }
    //} else {
    //    panic!("Unsupported algo!");
    //}

    Ok((builder.build()?, private))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
