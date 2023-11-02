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

use crate::{
    types::{Ed25519SecretKey, KeyId},
    Ed25519PublicKey,
};

#[derive(Serialize, Deserialize)]
#[serde(from = "PseudoIDsPickle")]
#[serde(into = "PseudoIDsPickle")]
pub(super) struct PseudoIDs {
    pub next_key_id: u64,
    pub public_keys: BTreeMap<KeyId, Ed25519PublicKey>,
    pub private_keys: BTreeMap<KeyId, Ed25519SecretKey>,
    pub key_ids_by_key: HashMap<Ed25519PublicKey, KeyId>,
    pub keys_by_room_id: BTreeMap<String, KeyId>,
}

impl Clone for PseudoIDs {
    fn clone(&self) -> Self {
        let mut private_keys: BTreeMap<KeyId, Ed25519SecretKey> = Default::default();

        for (k, v) in self.private_keys.iter() {
            private_keys.insert(*k, Ed25519SecretKey::from_slice(&*v.to_bytes()));
        }

        PseudoIDs {
            next_key_id: self.next_key_id,
            public_keys: self.public_keys.clone(),
            private_keys,
            key_ids_by_key: self.key_ids_by_key.clone(),
            keys_by_room_id: self.keys_by_room_id.clone(),
        }
    }
}

impl PseudoIDs {
    pub fn new() -> Self {
        Self {
            next_key_id: 0,
            public_keys: Default::default(),
            private_keys: Default::default(),
            key_ids_by_key: Default::default(),
            keys_by_room_id: Default::default(),
        }
    }

    pub fn get_secret_key(&self, public_key: &Ed25519PublicKey) -> Option<&Ed25519SecretKey> {
        self.key_ids_by_key.get(public_key).and_then(|key_id| self.private_keys.get(key_id))
    }

    pub(super) fn insert_secret_key(&mut self, key: Ed25519SecretKey) -> Ed25519PublicKey {
        let public_key = key.public_key();

        let key_id = KeyId(self.next_key_id);
        self.private_keys.insert(key_id, key);
        self.key_ids_by_key.insert(public_key, key_id);
        self.public_keys.insert(key_id, public_key);

        self.next_key_id = self.next_key_id.wrapping_add(1);

        public_key
    }

    pub(super) fn insert_secret_key_with_id(
        &mut self,
        key_id: KeyId,
        key: Ed25519SecretKey,
    ) -> Ed25519PublicKey {
        let public_key = key.public_key();

        self.private_keys.insert(key_id, key);
        self.key_ids_by_key.insert(public_key, key_id);
        self.public_keys.insert(key_id, public_key);

        public_key
    }

    fn generate_pseudoid(&mut self) -> Ed25519SecretKey {
        let key_id = KeyId(self.next_key_id);
        let key = Ed25519SecretKey::new();
        let key_copy = key.copy();
        self.insert_secret_key_with_id(key_id, key);

        key_copy
    }

    pub fn generate(&mut self) -> Ed25519SecretKey {
        let created = self.generate_pseudoid();
        self.next_key_id = self.next_key_id.wrapping_add(1);

        created
    }

    pub fn add_pseudoid_room_mapping(&mut self, room: &str, pseudoid: &Ed25519PublicKey) {
        self.key_ids_by_key
            .get(pseudoid)
            .and_then(|&key_id| self.keys_by_room_id.insert(room.to_string(), key_id));
    }

    pub fn get_pseudoid_for_room(&self, room: &str) -> Option<&Ed25519SecretKey> {
        tracing::info!("");
        self.keys_by_room_id.get(room).and_then(|key_id| self.private_keys.get(key_id))
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct PseudoIDsPickle {
    #[serde(alias = "key_id")]
    next_key_id: u64,
    public_keys: BTreeMap<KeyId, Ed25519PublicKey>,
    private_keys: BTreeMap<KeyId, Ed25519SecretKey>,
    keys_by_room_id: BTreeMap<String, KeyId>,
}

impl Clone for PseudoIDsPickle {
    fn clone(&self) -> Self {
        let mut private_keys: BTreeMap<KeyId, Ed25519SecretKey> = Default::default();

        for (k, v) in self.private_keys.iter() {
            private_keys.insert(*k, Ed25519SecretKey::from_slice(&*v.to_bytes()));
        }

        PseudoIDsPickle {
            next_key_id: self.next_key_id,
            public_keys: self.public_keys.clone(),
            private_keys,
            keys_by_room_id: self.keys_by_room_id.clone(),
        }
    }
}

impl From<PseudoIDsPickle> for PseudoIDs {
    fn from(pickle: PseudoIDsPickle) -> Self {
        let mut key_ids_by_key = HashMap::new();

        for (k, v) in pickle.private_keys.iter() {
            key_ids_by_key.insert(v.public_key(), *k);
        }

        Self {
            next_key_id: pickle.next_key_id,
            public_keys: pickle.public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: pickle.private_keys,
            key_ids_by_key,
            keys_by_room_id: pickle.keys_by_room_id,
        }
    }
}

impl From<PseudoIDs> for PseudoIDsPickle {
    fn from(keys: PseudoIDs) -> Self {
        PseudoIDsPickle {
            next_key_id: keys.next_key_id,
            public_keys: keys.public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: keys.private_keys,
            keys_by_room_id: keys.keys_by_room_id,
        }
    }
}
