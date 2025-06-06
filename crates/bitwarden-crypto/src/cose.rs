//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from <https://www.iana.org/assignments/cose/cose.xhtml> should always be preferred
//! unless there is a a clear benefit, such as a clear cryptographic benefit, which MUST
//! be documented publicly.

use coset::{
    iana::{self, CoapContentFormat},
    CborSerializable, ContentType, Label,
};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;
use typenum::U32;

use crate::{
    error::EncStringParseError, xchacha20, CryptoError, SymmetricCryptoKey, XChaCha20Poly1305Key,
};

/// XChaCha20 <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> is used over ChaCha20
/// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
/// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;
const XCHACHA20_TEXT_PAD_BLOCK_SIZE: usize = 32;
const CONTENT_TYPE_PADDED_UTF8: &str = "application/utf8-padded";

/// The content format describes the format of the contained bytes. Message encryption always
/// happens on the byte level, and this allows determining what format the contained data has. For
/// instance, an `EncString` in most cases contains UTF-8 encoded text. In some cases it may contain
/// a Pkcs8 private key, or a COSE key. Specifically, for COSE keys, this allows distinguishing
/// between the old symmetric key format, represented as `ContentFormat::OctetStream`, and the new
/// COSE key format, represented as `ContentFormat::CoseKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum ContentFormat {
    /// UTF-8 encoded text
    Utf8,
    /// Pkcs8 private key DER
    Pkcs8,
    /// COSE serialized CoseKey
    CoseKey,
    /// Stream of bytes
    OctetStream,
}

/// Encrypts a plaintext message using XChaCha20Poly1305 and returns a COSE Encrypt0 message
pub(crate) fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &crate::XChaCha20Poly1305Key,
    content_format: ContentFormat,
) -> Result<Vec<u8>, CryptoError> {
    let mut plaintext = plaintext.to_vec();

    let mut protected_header: coset::Header = content_format.into();

    if should_pad_content(&content_format) {
        // Pad the data to a block size in order to hide plaintext length
        crate::keys::utils::pad_bytes(&mut plaintext, XCHACHA20_TEXT_PAD_BLOCK_SIZE);
    }
    // This should be adjusted to use the builder pattern once implemented in coset.
    // The related coset upstream issue is:
    // https://github.com/google/coset/issues/105
    protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

    let mut nonce = [0u8; xchacha20::NONCE_SIZE];
    let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
        .protected(protected_header)
        .create_ciphertext(&plaintext, &[], |data, aad| {
            let ciphertext =
                crate::xchacha20::encrypt_xchacha20_poly1305(&(*key.enc_key).into(), data, aad);
            nonce = ciphertext.nonce();
            ciphertext.encrypted_bytes().to_vec()
        })
        .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
        .build();

    cose_encrypt0
        .to_vec()
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))
}

/// Decrypts a COSE Encrypt0 message, using a XChaCha20Poly1305 key
pub(crate) fn decrypt_xchacha20_poly1305(
    cose_encrypt0_message: &[u8],
    key: &crate::XChaCha20Poly1305Key,
) -> Result<(Vec<u8>, ContentFormat), CryptoError> {
    let msg = coset::CoseEncrypt0::from_slice(cose_encrypt0_message)
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))?;

    let Some(ref alg) = msg.protected.header.alg else {
        return Err(CryptoError::EncString(
            EncStringParseError::CoseMissingAlgorithm,
        ));
    };
    if *alg != coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) {
        return Err(CryptoError::WrongKeyType);
    }
    let content_format = ContentFormat::try_from(&msg.protected.header)
        .map_err(|_| CryptoError::EncString(EncStringParseError::CoseMissingContentType))?;

    let decrypted_message = msg.decrypt(&[], |data, aad| {
        let nonce = msg.unprotected.iv.as_slice();
        crate::xchacha20::decrypt_xchacha20_poly1305(
            nonce
                .try_into()
                .map_err(|_| CryptoError::InvalidNonceLength)?,
            &(*key.enc_key).into(),
            data,
            aad,
        )
    })?;

    if should_pad_content(&content_format) {
        // Unpad the data to get the original plaintext
        let data = crate::keys::utils::unpad_bytes(&decrypted_message)?;
        return Ok((data.to_vec(), content_format));
    }

    Ok((decrypted_message, content_format))
}

const SYMMETRIC_KEY: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);

impl TryFrom<&coset::CoseKey> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(cose_key: &coset::CoseKey) -> Result<Self, Self::Error> {
        let key_bytes = cose_key
            .params
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (&SYMMETRIC_KEY, ciborium::Value::Bytes(bytes)) => Some(bytes),
                _ => None,
            })
            .ok_or(CryptoError::InvalidKey)?;
        let alg = cose_key.alg.as_ref().ok_or(CryptoError::InvalidKey)?;

        match alg {
            coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) => {
                // Ensure the length is correct since `GenericArray::clone_from_slice` panics if it
                // receives the wrong length.
                if key_bytes.len() != xchacha20::KEY_SIZE {
                    return Err(CryptoError::InvalidKey);
                }
                let enc_key = Box::pin(GenericArray::<u8, U32>::clone_from_slice(key_bytes));
                let key_id = cose_key
                    .key_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey)?;
                Ok(SymmetricCryptoKey::XChaCha20Poly1305Key(
                    XChaCha20Poly1305Key { enc_key, key_id },
                ))
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

impl From<ContentFormat> for coset::Header {
    fn from(format: ContentFormat) -> Self {
        let header = coset::HeaderBuilder::new();
        let header = match format {
            ContentFormat::Utf8 => header.content_type(CONTENT_TYPE_PADDED_UTF8.to_string()),
            ContentFormat::Pkcs8 => header.content_format(CoapContentFormat::Pkcs8),
            ContentFormat::CoseKey => header.content_format(CoapContentFormat::CoseKey),
            ContentFormat::OctetStream => header.content_format(CoapContentFormat::OctetStream),
        };
        let mut header = header.build();
        // This should be adjusted to use the builder pattern once implemented in coset.
        // The related coset upstream issue is:
        // https://github.com/google/coset/issues/105
        header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));
        header
    }
}

impl TryFrom<&coset::Header> for ContentFormat {
    type Error = CryptoError;

    fn try_from(header: &coset::Header) -> Result<Self, Self::Error> {
        match header.content_type.as_ref() {
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_PADDED_UTF8 => {
                Ok(ContentFormat::Utf8)
            }
            Some(ContentType::Assigned(CoapContentFormat::Pkcs8)) => Ok(ContentFormat::Pkcs8),
            Some(ContentType::Assigned(CoapContentFormat::CoseKey)) => Ok(ContentFormat::CoseKey),
            Some(ContentType::Assigned(CoapContentFormat::OctetStream)) => {
                Ok(ContentFormat::OctetStream)
            }
            _ => Err(CryptoError::EncString(
                EncStringParseError::CoseMissingContentType,
            )),
        }
    }
}

fn should_pad_content(format: &ContentFormat) -> bool {
    matches!(format, ContentFormat::Utf8)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_octetstream() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted =
            encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::OctetStream).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::OctetStream));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_utf8() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::Utf8).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::Utf8));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_pkcs8() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::Pkcs8).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::Pkcs8));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_cosekey() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::CoseKey).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::CoseKey));
    }
}
