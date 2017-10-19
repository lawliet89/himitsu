extern crate argon2rs;
extern crate ring;
extern crate rmp_serde as rmps;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate strfmt;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use ring::aead;

/// Length of key, in bytes
pub const KEY_LENGTH: usize = 256 / 8;
/// Length of nonce in bytes
pub const NONCE_LENGTH: usize = 96 / 8;
/// Length of the tag, in bytes
pub const TAG_LENGTH: usize = 128 / 8;

/// Error type for returned errors
#[derive(Debug)]
pub enum Error {
    /// Error applying template
    TemplateError(strfmt::FmtError),
    /// Error encountered while packing data
    EncodingError(rmps::encode::Error),
    /// Error encountered while unpacking data
    DecodingError(rmps::decode::Error),
    /// Cryotpgraohic Error
    CryptographicError(ring::error::Unspecified),
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::TemplateError(ref e) => e.description(),
            Error::EncodingError(ref e) => e.description(),
            Error::DecodingError(ref e) => e.description(),
            Error::CryptographicError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::TemplateError(ref e) => Some(e),
            Error::EncodingError(ref e) => Some(e),
            Error::DecodingError(ref e) => Some(e),
            Error::CryptographicError(ref e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::TemplateError(ref e) => fmt::Display::fmt(e, f),
            Error::EncodingError(ref e) => fmt::Display::fmt(e, f),
            Error::DecodingError(ref e) => fmt::Display::fmt(e, f),
            Error::CryptographicError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

/// Implement a straightforward conversion of error type
macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

impl_from_error!(strfmt::FmtError, Error::TemplateError);
impl_from_error!(rmps::encode::Error, Error::EncodingError);
impl_from_error!(rmps::decode::Error, Error::DecodingError);
impl_from_error!(ring::error::Unspecified, Error::CryptographicError);

/// The vault of secrets and their associated launch parameters
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Vault {
    /// The secrets for a particular vault
    pub himitsu: Vec<Himitsu>,

    // TODO: Move nonce here? Ask the user not to touch the nonce field
}

/// The encrypted vault version. Defined as a struct for ease of serialization and deserialization
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedVault<'a> {
    /// The encrypted vault payload
    pub payload: Cow<'a, [u8]>,
    /// The AEAD tag from the encryption
    pub tag: Cow<'a, [u8]>,
    /// Salt use to derive the key
    pub salt: Cow<'a, [u8]>,
    /// Nonce used for encryption
    pub nonce: Cow<'a, [u8]>,
}

/// A specific secret
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Himitsu {
    /// Name of the secret for user identification
    pub name: String,
    /// The template where the secrets will be templated into
    pub template: String,
    /// Hash map of Secrets with their associated key
    // Note: This HashMap _must be_ the last: See https://github.com/alexcrichton/toml-rs/issues/142
    pub secrets: HashMap<String, String>,
}

impl Vault {
    /// Based on the provided password, salt, and nonce, encrypt the vault
    ///
    /// The salt must be between between 8 and 2^32-1 bytes
    /// The nonce must be 12 bytes long
    pub fn encrypt(&self, password: &[u8], salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
        let encrypted_vault = EncryptedVault::encrypt(self, password, salt, nonce)?;
        encrypted_vault.pack()
    }

    /// Based on the provided encrypted payload and password, decrypt the vault
    pub fn decrypt(encrypted_vault: &[u8], password: &[u8]) -> Result<Self, Error> {
        let vault = EncryptedVault::unpack(encrypted_vault)?;
        vault.decrypt(password)
    }
}

impl<'a> EncryptedVault<'a> {
    /// Based on an input password, and a salt, derive a key for use with `ChaCha20-Poly1305`.
    fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LENGTH] {
        let mut out = [0; KEY_LENGTH];
        let a2 = argon2rs::Argon2::default(argon2rs::Variant::Argon2i);
        a2.hash(&mut out, password, salt, &[], &[]);
        out
    }

    /// Based on a decrypted vault, create an encrpyted vault
    pub fn encrypt(
        vault: &Vault,
        password: &[u8],
        salt: &'a [u8],
        nonce: &'a [u8],
    ) -> Result<Self, Error> {
        let key = Self::derive_key(password, salt);
        let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &key)?;

        let mut payload = rmps::to_vec_named(vault)?;
        payload.append(&mut vec![0; TAG_LENGTH]);

        let size = aead::seal_in_place(&sealing_key, nonce, &[], &mut payload, TAG_LENGTH)?;

        Ok(Self {
            payload: Cow::Owned(payload[0..(size - TAG_LENGTH)].to_vec()),
            tag: Cow::Owned(payload[(size - TAG_LENGTH)..size].to_vec()),
            salt: From::from(salt),
            nonce: From::from(nonce),
        })
    }

    /// Given an encrypted payload, decrypt the vault
    pub fn decrypt(&self, password: &[u8]) -> Result<Vault, Error> {
        let key = Self::derive_key(password, &self.salt);
        let opening_key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &key)?;

        let mut payload = self.payload.to_vec();
        payload.append(&mut self.tag.to_vec());

        let plaintext = aead::open_in_place(&opening_key, &self.nonce, &[], 0, &mut payload)?;

        Ok(rmps::from_slice(plaintext)?)
    }

    /// Pack the encrypted vault into a binary format
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        Ok(rmps::to_vec_named(self)?)
    }

    /// Unpack a given slice into the encrypted form
    pub fn unpack(packed: &'a [u8]) -> Result<Self, Error> {
        Ok(rmps::from_slice(packed)?)
    }
}


impl Himitsu {
    /// Apply the template string with the secrets
    pub fn apply(&self) -> Result<String, Error> {
        Ok(strfmt::strfmt(&self.template, &self.secrets)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vault() -> Vault {
        let secrets = vec![make_himitsu(), make_himitsu(), make_himitsu()];
        Vault { himitsu: secrets }
    }

    fn make_himitsu() -> Himitsu {
        Himitsu {
            name: "Test".to_string(),
            secrets: vec![
                ("secret".to_string(), "foo".to_string()),
                ("secret2".to_string(), "bar".to_string()),
            ].into_iter()
                .collect(),
            template: "{secret} is {secret2}".to_string(),
        }
    }

    #[test]
    fn himitsu_template_is_applied_correctly() {
        let himitsu = make_himitsu();

        let applied = himitsu.apply().expect("to be successful");
        let expected_applied = "foo is bar";

        assert_eq!(expected_applied, &applied);
    }

    #[test]
    fn vault_encryption_roundtrip() {
        let password = "foobarbaz";

        let salt = vec![0; 32];
        let nonce = vec![0; 12];

        let vault = make_vault();

        let encrypted_vault = vault
            .encrypt(password.as_bytes(), &salt, &nonce)
            .expect("to work");
        let decrypted_vault =
            Vault::decrypt(&encrypted_vault, password.as_bytes()).expect("to not fail");

        assert_eq!(vault, decrypted_vault);
    }
}
