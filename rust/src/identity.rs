//! The keypair, and the request that asks for a certificate over it.
//!
//! THE PRIVATE KEY IS GENERATED HERE AND NEVER LEAVES. That is the whole
//! reason there is a certificate request at all: the api's `services/pki.py`
//! takes the public key out of the CSR and throws the rest away, so the only
//! thing that crosses the wire is a public key and a proof that this device
//! holds the other half of it.
//!
//! It is worth naming the alternative, because a sibling product ships it: the
//! v5 install flow has the backend mint the keypair and send the private key
//! back over HTTPS in base64. That works, and it means the key existed on a
//! server, in a log-capable request body, before it reached the device.

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

use crate::error::{Error, Result};

pub struct Identity {
    /// PKCS#8. `KeyPair::serialize_pem` emits `BEGIN PRIVATE KEY`, which is
    /// what `mqtt::private_key` reads first.
    pub private_key_pem: String,
    pub csr_pem: String,
}

/// A fresh P-256 keypair and a certificate request naming `common_name`.
///
/// P-256 AND NOTHING ELSE, because `pki.public_key_from_csr` refuses anything
/// else and a device that generated an RSA key would find that out from a 400
/// with no useful detail.
///
/// The common name in the request is cosmetic: the api discards the subject and
/// signs the name in its own records, on the grounds that a device proves it
/// holds a key and does not get to say what the certificate calls it. It is
/// filled in anyway so a CSR in a log is identifiable.
pub fn generate(common_name: &str) -> Result<Identity> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|error| Error::Crypto(format!("could not generate a P-256 key: {error}")))?;
    let private_key_pem = key.serialize_pem();

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);

    let csr_pem = params
        .serialize_request(&key)
        .map_err(|error| Error::Crypto(format!("could not build a certificate request: {error}")))?
        .pem()
        .map_err(|error| {
            Error::Crypto(format!("could not encode the certificate request: {error}"))
        })?;

    Ok(Identity {
        private_key_pem,
        csr_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_carries_a_pkcs8_key_and_a_pem_csr() {
        let identity = generate("acme/production/pump-3").unwrap();
        assert!(identity
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(identity
            .csr_pem
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    }

    #[test]
    fn every_device_gets_its_own_key() {
        let one = generate("acme/production/pump-3").unwrap();
        let two = generate("acme/production/pump-3").unwrap();
        assert_ne!(one.private_key_pem, two.private_key_pem);
    }
}
