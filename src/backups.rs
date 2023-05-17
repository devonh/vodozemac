// Copyright 2023 Damir Jelić
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ☣️  Support for Olms PkEncryption and PkDecryption
//!
//! This sucks, don't use it.

use aes::{
    cipher::{
        block_padding::{Pkcs7, UnpadError},
        generic_array::GenericArray,
        BlockDecryptMut, BlockEncryptMut, IvSizeUser, KeyIvInit, KeySizeUser,
    },
    Aes256,
};
use hkdf::Hkdf;
use hmac::{digest::MacError, Hmac, Mac as MacT};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::SharedSecret;

use crate::{types::Curve25519SecretKey, Curve25519PublicKey};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

type Aes256Key = GenericArray<u8, <Aes256 as KeySizeUser>::KeySize>;
type Aes256Iv = GenericArray<u8, <Aes256CbcEnc as IvSizeUser>::IvSize>;
type HmacSha256Key<'a> = &'a [u8; 32];

pub struct PkDecryption {
    key: Curve25519SecretKey,
    public_key: Curve25519PublicKey,
}

struct Keys {
    aes_key: Box<[u8; 32]>,
    mac_key: Box<[u8; 32]>,
    iv: Box<[u8; 16]>,
}

impl Keys {
    fn new(shared_secret: SharedSecret) -> Self {
        let mut expanded_keys = Box::new([0u8; 80]);

        let salt = [0u8; 32];
        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&salt), shared_secret.as_bytes());

        hkdf.expand(b"", &mut *expanded_keys)
            .expect("We should be able to expand the shared secret into 80 bytes");

        let mut aes_key = Box::new([0u8; 32]);
        let mut mac_key = Box::new([0u8; 32]);
        let mut iv = Box::new([0u8; 16]);

        aes_key.copy_from_slice(&expanded_keys[0..32]);
        mac_key.copy_from_slice(&expanded_keys[32..64]);
        iv.copy_from_slice(&expanded_keys[64..80]);

        Self { aes_key, mac_key, iv }
    }

    fn aes_key(&self) -> &Aes256Key {
        Aes256Key::from_slice(self.aes_key.as_slice())
    }

    fn iv(&self) -> &Aes256Iv {
        Aes256Iv::from_slice(self.iv.as_slice())
    }

    fn mac_key(&self) -> HmacSha256Key<'_> {
        &self.mac_key
    }

    fn hmac(&self, ciphertext: &[u8]) -> HmacSha256 {
        // 🥧
        let mac_thing: Vec<u8> = vec![0; ciphertext.len()];

        let mut hmac = HmacSha256::new_from_slice(self.mac_key())
            .expect("We should be able to create a Hmac object from a 32 byte key");

        hmac.update(&mac_thing);

        hmac
    }
}

impl PkDecryption {
    pub fn new() -> Self {
        let key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&key);

        Self { key, public_key }
    }

    pub fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }

    pub fn decrypt(&self, message: &Message) -> Result<Vec<u8>, Error> {
        let shared_secret = self.key.diffie_hellman(&message.ephemeral_key);

        let keys = Keys::new(shared_secret);

        let cipher = Aes256CbcDec::new(keys.aes_key(), keys.iv());
        let decrypted = cipher.decrypt_padded_vec_mut::<Pkcs7>(&message.ciphertext)?;

        let hmac = keys.hmac(&message.ciphertext);
        hmac.verify_truncated_left(&message.mac)?;

        Ok(decrypted)
    }
}

impl Default for PkDecryption {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PkEncryption {
    public_key: Curve25519PublicKey,
}

impl From<&PkDecryption> for PkEncryption {
    fn from(value: &PkDecryption) -> Self {
        Self::from(value.public_key())
    }
}

impl From<Curve25519PublicKey> for PkEncryption {
    fn from(public_key: Curve25519PublicKey) -> Self {
        Self { public_key }
    }
}

impl PkEncryption {
    pub fn new() -> Self {
        let key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&key);

        Self { public_key }
    }

    pub fn encrypt(&self, message: &[u8]) -> Message {
        let ephemeral_key = Curve25519SecretKey::new();
        let shared_secret = ephemeral_key.diffie_hellman(&self.public_key);
        let keys = Keys::new(shared_secret);

        let cipher = Aes256CbcEnc::new(keys.aes_key(), keys.iv());
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(message);

        let hmac = keys.hmac(&ciphertext);
        let mac = hmac.finalize().into_bytes().to_vec();

        Message { ciphertext, mac, ephemeral_key: Curve25519PublicKey::from(&ephemeral_key) }
    }
}

pub struct Message {
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub ephemeral_key: Curve25519PublicKey,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed decrypting, invalid padding")]
    InvalidPadding(#[from] UnpadError),
    #[error("The MAC of the ciphertext didn't pass validation {0}")]
    Mac(#[from] MacError),
}

#[cfg(test)]
mod test {
    use olm_rs::pk::{OlmPkEncryption, PkMessage};

    use super::*;
    use crate::utilities::base64_decode;

    impl TryFrom<PkMessage> for Message {
        type Error = base64::DecodeError;

        fn try_from(value: PkMessage) -> Result<Self, Self::Error> {
            Ok(Self {
                ciphertext: base64_decode(value.ciphertext)?,
                mac: base64_decode(value.mac)?,
                ephemeral_key: Curve25519PublicKey::from_base64(&value.ephemeral_key).unwrap(),
            })
        }
    }

    #[test]
    fn decrypt() {
        let decryptor = PkDecryption::new();
        let public_key = decryptor.public_key();
        let encryptor = OlmPkEncryption::new(&public_key.to_base64());

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message);
        let encrypted = encrypted.try_into().unwrap();

        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(message.as_bytes(), decrypted);

        println!("{}", String::from_utf8_lossy(&decrypted));

        todo!()
    }
}
