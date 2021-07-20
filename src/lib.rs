use serde::{Deserialize, Serialize};
use tss_esapi::attributes::object::ObjectAttributesBuilder;
use tss_esapi::constants::tss::*;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::tss2_esys::TPM2B_PUBLIC;
use tss_esapi::utils::Tpm2BPublicBuilder;
use tss_esapi::utils::{AsymSchemeUnion, PublicParmsUnion, TpmsRsaParmsBuilder};
use tss_esapi::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Description {
    pub spec: Specification,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Specification {
    pub provider: Provider,
    pub algo: AlgorithmSpec,
    pub capabilities: Vec<Capability>,
    pub auth: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Decrypt,
    Sign,
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
    pub handle: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub bytes: String,
    pub manu: Option<u32>,
    pub name: String,
}

pub fn create(spec: &Specification) -> Result<TPM2B_PUBLIC> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(spec.capabilities.contains(&Capability::Decrypt))
        .with_sign_encrypt(spec.capabilities.contains(&Capability::Sign))
        .with_restricted(false)
        .build()?;

    let mut builder = Tpm2BPublicBuilder::new()
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(attributes);

    //if let Rsa = &spec.algo.pk {
    let rsa_params = TpmsRsaParmsBuilder {
        symmetric: None,
        scheme: Some(AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256)),
        key_bits: spec.algo.bits,
        exponent: 0,
        for_signing: spec.capabilities.contains(&Capability::Sign),
        for_decryption: spec.capabilities.contains(&Capability::Decrypt),
        restricted: false,
    }
    .build()?;

    builder = builder
        .with_type(TPM2_ALG_RSA)
        .with_parms(PublicParmsUnion::RsaDetail(rsa_params));
    //} else {
    //    panic!("Unsupported algo!");
    //}

    builder.build()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
