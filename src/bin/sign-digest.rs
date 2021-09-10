use std::borrow::Cow;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;
use tpm_openpgp::Description;
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::session_type::SessionType;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use tss_esapi::structures::{Digest, Signature, SymmetricDefinition};
use tss_esapi::{Context, Tcti};

use tss_esapi::tss2_esys::{TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK};

use tss_esapi::constants::tss::{TPM2_ALG_NULL, TPM2_RH_NULL, TPM2_ST_HASHCHECK};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    file: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    let deserialized: Description = serde_yaml::from_reader(File::open(opt.file)?)?;

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
    context
        .tr_sess_set_attributes(session.unwrap(), session_attr, session_mask)
        .unwrap();
    context.set_sessions((session, None, None));

    let key_handle = tpm_openpgp::convert_to_key_handle(&mut context, &deserialized.spec)?;

    let scheme = TPMT_SIG_SCHEME {
        scheme: TPM2_ALG_NULL,
        details: Default::default(),
    };
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    }
    .try_into()?;

    let mut hash = vec![0; 32];
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle.read_exact(&mut hash)?;

    let digest = &Digest::try_from(hash)?;

    let signature = context.sign(key_handle, digest, scheme, validation)?;

    let signature = match signature {
        Signature::RsaSsa(ref signature) => Cow::Borrowed(signature.signature().value()),
        Signature::EcDsa(signature) => {
            let mut sig = vec![];
            sig.extend(signature.signature_r().value());
            sig.extend(signature.signature_s().value());
            Cow::Owned(sig)
        }
        _ => panic!("Unsupported signature scheme."),
    };

    let mut stdout = std::io::stdout();
    stdout.write_all(&signature)?;

    Ok(())
}
