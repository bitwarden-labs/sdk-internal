use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

use crate::{
    error::{Result, RsaError, UnsupportedOperation},
    CryptoError, EncString, SymmetricCryptoKey,
};

/// RSA Key Pair
///
/// Consists of a public key and an encrypted private key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RsaKeyPair {
    /// Base64 encoded DER representation of the public key
    pub public: String,
    /// Encrypted PKCS8 private key
    pub private: EncString,
}

/// Generate a new RSA key pair of 2048 bits
pub(crate) fn make_key_pair(key: &SymmetricCryptoKey) -> Result<RsaKeyPair> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let spki = pub_key
        .to_public_key_der()
        .map_err(|_| RsaError::CreatePublicKey)?;

    let b64 = STANDARD.encode(spki.as_bytes());
    let pkcs = priv_key
        .to_pkcs8_der()
        .map_err(|_| RsaError::CreatePrivateKey)?;

    let protected = match key {
        SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
            EncString::encrypt_aes256_hmac(pkcs.as_bytes(), key)
        }
        SymmetricCryptoKey::XChaCha20Poly1305Key(_) => Err(CryptoError::OperationNotSupported(
            UnsupportedOperation::EncryptionNotImplementedForKey,
        )),
        SymmetricCryptoKey::Aes256CbcKey(_) => Err(CryptoError::OperationNotSupported(
            UnsupportedOperation::EncryptionNotImplementedForKey,
        )),
    }?;

    Ok(RsaKeyPair {
        public: b64,
        private: protected,
    })
}
