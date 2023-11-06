// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use tracing::info;

use super::PUBLIC_MAX_ONE_TIME_KEYS;
use crate::{
    types::{Ed25519SecretKey, KeyId},
    Ed25519PublicKey,
};

#[derive(Serialize, Deserialize)]
#[serde(from = "OneTimePseudoIDsPickle")]
#[serde(into = "OneTimePseudoIDsPickle")]
pub(super) struct OneTimePseudoIDs {
    pub next_key_id: u64,
    pub unpublished_public_keys: BTreeMap<KeyId, Ed25519PublicKey>,
    pub private_keys: BTreeMap<KeyId, Ed25519SecretKey>,
    pub key_ids_by_key: HashMap<Ed25519PublicKey, KeyId>,
}

impl Clone for OneTimePseudoIDs {
    fn clone(&self) -> Self {
        let mut private_keys: BTreeMap<KeyId, Ed25519SecretKey> = Default::default();

        for (k, v) in self.private_keys.iter() {
            private_keys.insert(*k, Ed25519SecretKey::from_slice(&*v.to_bytes()));
        }

        OneTimePseudoIDs {
            next_key_id: self.next_key_id,
            unpublished_public_keys: self.unpublished_public_keys.clone(),
            private_keys,
            key_ids_by_key: self.key_ids_by_key.clone(),
        }
    }
}

/// The result type for the one-time pseudoID generation operation.
pub struct OneTimePseudoIDGenerationResult {
    /// The public part of the one-time pseudoIDs that were newly generated.
    pub created: Vec<Ed25519PublicKey>,
    /// The public part of the one-time pseudoIDs that had to be removed to make
    /// space for the new ones.
    pub removed: Vec<Ed25519PublicKey>,
}

impl OneTimePseudoIDs {
    const MAX_ONE_TIME_PSEUDOIDS: usize = 100 * PUBLIC_MAX_ONE_TIME_KEYS;

    pub fn new() -> Self {
        Self {
            next_key_id: 0,
            unpublished_public_keys: Default::default(),
            private_keys: Default::default(),
            key_ids_by_key: Default::default(),
        }
    }

    pub fn mark_as_published(&mut self) {
        self.unpublished_public_keys.clear();
    }

    //pub fn get_secret_key(&self, public_key: &Ed25519PublicKey) ->
    // Option<&Ed25519SecretKey> {    self.key_ids_by_key.get(public_key).
    // and_then(|key_id| self.private_keys.get(key_id)) }

    pub fn remove_secret_key(&mut self, public_key: &Ed25519PublicKey) -> Option<Ed25519SecretKey> {
        info!("Removing secret key for {}: Keys: {:?}", public_key, self.key_ids_by_key);
        self.key_ids_by_key.remove(public_key).and_then(|key_id| {
            self.unpublished_public_keys.remove(&key_id);
            self.private_keys.remove(&key_id)
        })
    }

    pub(super) fn insert_secret_key(
        &mut self,
        key_id: KeyId,
        key: Ed25519SecretKey,
        published: bool,
    ) -> (Ed25519PublicKey, Option<Ed25519PublicKey>) {
        // If we hit the max number of one-time pseudoIDs we'd like to keep, first
        // remove one before we create a new one.
        let removed = if self.private_keys.len() >= Self::MAX_ONE_TIME_PSEUDOIDS {
            if let Some(key_id) = self.private_keys.keys().next().copied() {
                let public_key = if let Some(private_key) = self.private_keys.remove(&key_id) {
                    let public_key = private_key.public_key();
                    self.key_ids_by_key.remove(&public_key);

                    Some(public_key)
                } else {
                    None
                };

                self.unpublished_public_keys.remove(&key_id);

                public_key
            } else {
                None
            }
        } else {
            None
        };

        let public_key = key.public_key();

        self.private_keys.insert(key_id, key);
        self.key_ids_by_key.insert(public_key, key_id);

        if !published {
            self.unpublished_public_keys.insert(key_id, public_key);
        }

        (public_key, removed)
    }

    fn generate_one_time_key(&mut self) -> (Ed25519PublicKey, Option<Ed25519PublicKey>) {
        let key_id = KeyId(self.next_key_id);
        let key = Ed25519SecretKey::new();
        self.insert_secret_key(key_id, key, false)
    }

    //pub(crate) fn secret_keys(&self) -> &BTreeMap<KeyId, Ed25519SecretKey> {
    //    &self.private_keys
    //}

    //pub(crate) fn is_secret_key_published(&self, key_id: &KeyId) -> bool {
    //    !self.unpublished_public_keys.contains_key(key_id)
    //}

    pub fn generate(&mut self, count: usize) -> OneTimePseudoIDGenerationResult {
        let mut removed_keys = Vec::new();
        let mut created_keys = Vec::new();

        for _ in 0..count {
            let (created, removed) = self.generate_one_time_key();

            created_keys.push(created);
            if let Some(removed) = removed {
                removed_keys.push(removed);
            }

            self.next_key_id = self.next_key_id.wrapping_add(1);
        }

        OneTimePseudoIDGenerationResult { created: created_keys, removed: removed_keys }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct OneTimePseudoIDsPickle {
    #[serde(alias = "key_id")]
    next_key_id: u64,
    public_keys: BTreeMap<KeyId, Ed25519PublicKey>,
    private_keys: BTreeMap<KeyId, Ed25519SecretKey>,
}

impl Clone for OneTimePseudoIDsPickle {
    fn clone(&self) -> Self {
        let mut private_keys: BTreeMap<KeyId, Ed25519SecretKey> = Default::default();

        for (k, v) in self.private_keys.iter() {
            private_keys.insert(*k, Ed25519SecretKey::from_slice(&*v.to_bytes()));
        }

        OneTimePseudoIDsPickle {
            next_key_id: self.next_key_id,
            public_keys: self.public_keys.clone(),
            private_keys,
        }
    }
}

impl From<OneTimePseudoIDsPickle> for OneTimePseudoIDs {
    fn from(pickle: OneTimePseudoIDsPickle) -> Self {
        let mut key_ids_by_key = HashMap::new();

        for (k, v) in pickle.private_keys.iter() {
            key_ids_by_key.insert(v.public_key(), *k);
        }

        info!("One-Time PseudoIDs: {:?}", key_ids_by_key);
        Self {
            next_key_id: pickle.next_key_id,
            unpublished_public_keys: pickle.public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: pickle.private_keys,
            key_ids_by_key,
        }
    }
}

impl From<OneTimePseudoIDs> for OneTimePseudoIDsPickle {
    fn from(keys: OneTimePseudoIDs) -> Self {
        OneTimePseudoIDsPickle {
            next_key_id: keys.next_key_id,
            public_keys: keys.unpublished_public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: keys.private_keys,
        }
    }
}

#[cfg(test)]
mod test {
    use super::OneTimePseudoIDs;
    use crate::types::KeyId;

    #[test]
    fn store_limit() {
        let mut store = OneTimePseudoIDs::new();

        assert!(store.private_keys.is_empty());

        store.generate(OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);
        assert_eq!(store.private_keys.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);
        assert_eq!(store.unpublished_public_keys.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);
        assert_eq!(store.key_ids_by_key.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);

        store.mark_as_published();
        assert!(store.unpublished_public_keys.is_empty());
        assert_eq!(store.private_keys.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);
        assert_eq!(store.key_ids_by_key.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);

        let oldest_key_id =
            store.private_keys.keys().next().copied().expect("Couldn't get the first key ID");
        assert_eq!(oldest_key_id, KeyId(0));

        store.generate(10);
        assert_eq!(store.unpublished_public_keys.len(), 10);
        assert_eq!(store.private_keys.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);
        assert_eq!(store.key_ids_by_key.len(), OneTimePseudoIDs::MAX_ONE_TIME_PSEUDOIDS);

        let oldest_key_id =
            store.private_keys.keys().next().copied().expect("Couldn't get the first key ID");

        assert_eq!(oldest_key_id, KeyId(10));
    }
}
