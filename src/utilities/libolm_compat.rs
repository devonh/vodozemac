// Copyright 2021 Damir Jelić
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

use std::io::{Cursor, Read, Write};

use thiserror::Error;
use zeroize::Zeroize;

use super::base64_decode;
use crate::{cipher::Cipher, LibolmPickleError};

const MAX_ARRAY_LENGTH: usize = u16::MAX as usize;

/// Error type describing failure modes for libolm pickle decoding.
#[derive(Debug, Error)]
pub enum LibolmDecodeError {
    /// There was an error while reading from the source of the libolm, usually
    /// not enough data was provided.
    #[error(transparent)]
    IO(#[from] std::io::Error),
    /// The encoded usize doesn't fit into the usize of the architecture that is
    /// decoding.
    #[error(
        "The decoded value {0} does not fit into the usize type of this \
         architecture"
    )]
    OutsideUsizeRange(u64),
    /// An array in the pickle has too many elements.
    #[error("An array has too many elements: {0}")]
    ArrayTooBig(usize),
}

/// Error type describing failure modes for libolm pickle decoding.
#[derive(Debug, Error)]
pub enum LibolmEncodeError {
    /// There was an error while writing to the buffer.
    #[error(transparent)]
    IO(#[from] std::io::Error),
    /// The usize value that should be encoded doesn't fit into the u32 range of
    /// values.
    #[error("The usize value {0} does not fit into the u32 range of values.")]
    OutsideU32Range(usize),
    /// An array in the pickle has too many elements.
    #[error("An array has too many elements: {0}")]
    ArrayTooBig(usize),
}

/// Decrypt and decode the given pickle with the given pickle key.
///
/// # Arguments
///
/// * pickle - The base64-encoded and encrypted libolm pickle string
/// * pickle_key - The key that was used to encrypt the libolm pickle
/// * pickle_version - The expected version of the pickle. Unpickling will fail
///   if the version in the pickle doesn't match this one.
pub(crate) fn unpickle_libolm<P: Decode, T: TryFrom<P, Error = LibolmPickleError>>(
    pickle: &str,
    pickle_key: &[u8],
    pickle_version: u32,
) -> Result<T, LibolmPickleError> {
    /// Fetch the pickle version from the given pickle source.
    fn get_version(source: &[u8]) -> Option<u32> {
        // Pickle versions are always u32 encoded as a fixed sized integer in
        // big endian encoding.
        let version = source.get(0..4)?;
        Some(u32::from_be_bytes(version.try_into().ok()?))
    }

    // libolm pickles are always base64 encoded, so first try to decode.
    let decoded = base64_decode(pickle)?;

    // The pickle is always encrypted, even if a zero key is given. Try to
    // decrypt next.
    let cipher = Cipher::new_pickle(pickle_key);
    let mut decrypted = cipher.decrypt_pickle(&decoded)?;

    // A pickle starts with a version, which will decide how we need to decode.
    // We only support the latest version so bail out if it isn't the expected
    // pickle version.
    let version = get_version(&decrypted).ok_or(LibolmPickleError::MissingVersion)?;

    if version == pickle_version {
        let mut cursor = Cursor::new(&decrypted);
        let pickle = P::decode(&mut cursor)?;

        decrypted.zeroize();
        pickle.try_into()
    } else {
        Err(LibolmPickleError::Version(pickle_version, version))
    }
}

/// A trait for decoding non-secret values out of a libolm-compatible pickle.
///
/// This is almost exactly the same as what the [bincode] crate provides with
/// the following config:
/// ```rust,compile_fail
/// let config = bincode::config::standard()
///     .with_big_endian()
///     .with_fixed_int_encoding()
///     .skip_fixed_array_length();
/// ```
///
/// The two major differences are:
/// * bincode uses u64 to encode slice lengths
/// * libolm uses u32 to encode slice lengths expect for fallback keys, where an
///   u8 is used
///
/// The following Decode implementations decode primitive types in a libolm
/// compatible way.
///
/// For decoding values which are meant to be secret, see `DecodeSecret`.
///
/// [bincode]: https://github.com/bincode-org/bincode/
pub(crate) trait Decode {
    /// Try to read and decode a non-secret value from the given reader which is
    /// reading from a libolm-compatible pickle.
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError>
    where
        Self: Sized;

    /// Try to read and decode a value from the given byte slice.
    fn decode_from_slice(buffer: &[u8]) -> Result<Self, LibolmDecodeError>
    where
        Self: Sized,
    {
        let mut cursor = Cursor::new(buffer);
        Self::decode(&mut cursor)
    }
}

/// Like `Decode`, but for decoding secret values.
///
/// Unlike `Decode`, this trait allocates the buffer for the target value on the
/// heap and returns it in a `Box`. This reduces the number of inadvertent
/// copies made when the value is moved, allowing the value to be properly
/// zeroized.
pub(crate) trait DecodeSecret {
    /// Try to read and decode a secret value from the given reader which is
    /// reading from a libolm-compatible pickle.
    fn decode_secret(reader: &mut impl Read) -> Result<Box<Self>, LibolmDecodeError>
    where
        Self: Sized;
}

impl Decode for u8 {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; 1];

        reader.read_exact(&mut buffer)?;

        Ok(buffer[0])
    }
}

impl Decode for bool {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let value = u8::decode(reader)?;

        Ok(value != 0)
    }
}

impl Decode for u32 {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;

        Ok(u32::from_be_bytes(buffer))
    }
}

impl Decode for usize {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let size = u32::decode(reader)?;

        size.try_into().map_err(|_| LibolmDecodeError::OutsideUsizeRange(size as u64))
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; N];
        reader.read_exact(&mut buffer)?;

        Ok(buffer)
    }
}

impl<const N: usize> DecodeSecret for [u8; N] {
    fn decode_secret(reader: &mut impl Read) -> Result<Box<Self>, LibolmDecodeError> {
        let mut buffer = Box::new([0u8; N]);
        reader.read_exact(buffer.as_mut_slice())?;

        Ok(buffer)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let length = usize::decode(reader)?;

        if length > MAX_ARRAY_LENGTH {
            Err(LibolmDecodeError::ArrayTooBig(length))
        } else {
            let mut buffer = Vec::with_capacity(length);

            for _ in 0..length {
                let element = T::decode(reader)?;
                buffer.push(element);
            }

            Ok(buffer)
        }
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct LibolmEd25519Keypair {
    pub public_key: [u8; 32],
    pub private_key: Box<[u8; 64]>,
}

impl Decode for LibolmEd25519Keypair {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError>
    where
        Self: Sized,
    {
        let public_key = <[u8; 32]>::decode(reader)?;
        let private_key = <[u8; 64]>::decode_secret(reader)?;

        Ok(Self { public_key, private_key })
    }
}

pub trait Encode {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError>;

    fn encode_to_vec(&self) -> Result<Vec<u8>, LibolmEncodeError> {
        let buffer = Vec::new();
        let mut cursor = Cursor::new(buffer);

        self.encode(&mut cursor)?;

        Ok(cursor.into_inner())
    }
}

impl Encode for u8 {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        Ok(writer.write(&[*self])?)
    }
}

impl Encode for bool {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        (*self as u8).encode(writer)
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        writer.write_all(self)?;

        Ok(self.len())
    }
}

impl Encode for u32 {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        let bytes = self.to_be_bytes();
        bytes.encode(writer)
    }
}

impl Encode for usize {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        let value = u32::try_from(*self).map_err(|_| LibolmEncodeError::OutsideU32Range(*self))?;

        value.encode(writer)
    }
}

impl<T: Encode> Encode for [T] {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        let length = self.len();

        if length > MAX_ARRAY_LENGTH {
            Err(LibolmEncodeError::ArrayTooBig(length))
        } else {
            let mut ret = length.encode(writer)?;

            for value in self {
                ret += value.encode(writer)?;
            }

            Ok(ret)
        }
    }
}

impl Encode for LibolmEd25519Keypair {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, LibolmEncodeError> {
        let mut ret = self.public_key.encode(writer)?;
        ret += self.private_key.encode(writer)?;

        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    macro_rules! encode_cycle {
        ($value:expr => $type:ty) => {
            let value = $value;

            let encoded = value.encode_to_vec().expect("We can always encode into to a Vec");
            let decoded = <$type>::decode_from_slice(&encoded)
                .expect("Decoding a freshly encoded value always works");

            assert_eq!(value, decoded, "The original value and the decoded value are not the same");
        };
    }

    #[test]
    fn encode_cycle() {
        let key_pair =
            LibolmEd25519Keypair { public_key: [10u8; 32], private_key: [20u8; 64].into() };

        encode_cycle!(10u8 => u8);
        encode_cycle!(10u32 => u32);
        encode_cycle!(10usize => usize);
        encode_cycle!(true => bool);
        encode_cycle!(false => bool);
        encode_cycle!(vec![1, 2, 3, 4] => Vec<u8>);

        let encoded = key_pair.encode_to_vec().unwrap();
        let decoded = LibolmEd25519Keypair::decode_from_slice(&encoded).unwrap();

        assert_eq!(key_pair.public_key, decoded.public_key);
        assert_eq!(key_pair.private_key, decoded.private_key);
    }

    proptest! {
        #[test]
        fn encode_cycle_u8(a in 0..u8::MAX) {
            encode_cycle!(a => u8);
        }

        #[test]
        fn encode_cycle_u32(a in 0..u32::MAX) {
            encode_cycle!(a => u32);
        }

        #[test]
        fn encode_cycle_usize(a in 0..u32::MAX) {
            let a = a as usize;
            encode_cycle!(a => usize);
        }

        fn encode_cycle_vec(bytes in prop::collection::vec(any::<u8>(), 0..1000)) {
            encode_cycle!(bytes => Vec<u8>);
        }
    }
}
