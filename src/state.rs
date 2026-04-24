/*
   Copyright 2026 SUSE LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */


use base64::prelude::*;

type StateId = u64;

#[derive(Eq, PartialEq, Hash)]
#[derive(Debug)]
pub struct StateKey {
    username: String,
    state_id: StateId,
}

impl StateKey {
    /// Some magic bytes not in the printable characters range.
    /// This is used to ensure we are actually dealing with a state set by us and not a user that has a password that looks like a CRV1 response.
    const MAGIC_BYTES: [u8; 3] = [0x11, 0xF, 0xA];
    const STATE_SIZE: usize = size_of_val(&Self::MAGIC_BYTES) + size_of::<StateId>();

    pub fn new(username: &str) -> Self {
        Self { username: String::from(username), state_id: rand::random::<StateId>() }
    }

    pub fn encoded_state(&self) -> String {
        let mut state = [0u8; Self::STATE_SIZE];
        state[..size_of_val(&Self::MAGIC_BYTES)].copy_from_slice(&Self::MAGIC_BYTES);
        state[size_of_val(&Self::MAGIC_BYTES)..].copy_from_slice(&self.state_id.to_be_bytes());
        BASE64_STANDARD.encode(state)
    }

    pub fn encoded_user(&self) -> String {
        BASE64_STANDARD.encode(&self.username)
    }

    pub fn from_state(user: &str, encoded_state: &str) -> Result<Self, String> {
        let Ok(state) = BASE64_STANDARD.decode(encoded_state) else {
            return Err(format!("Could not decode state {}", encoded_state));
        };

        if state.len() != Self::STATE_SIZE {
            return Err(format!("Could not decode state {}. Invalid length.", encoded_state));
        }

        let Some((magic, int_bytes)) = state.split_at_checked(size_of_val(&Self::MAGIC_BYTES)) else {
            return Err(format!("Could not decode state {}", encoded_state));
        };

        if magic != Self::MAGIC_BYTES {
            return Err(String::from("Magic bytes don't match."));
        }

        let Ok(int_bytes): Result<[u8;size_of::<StateId>()], _> = int_bytes.try_into() else {
            return Err(format!("Could not decode state {}", encoded_state));
        };

        let state_key = StateKey {
            username: String::from(user),
            state_id: StateId::from_be_bytes(int_bytes),
        };

        Ok(state_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_roundtrip() {
        let user = "test";
        let state_key = StateKey {
            username: String::from(user),
            state_id: 0x3C_66_3D_1E_20_2A_60_E0,
        };

        let encoded = state_key.encoded_state();
        let decoded = StateKey::from_state(user, &encoded);

        assert_eq!(state_key, decoded.unwrap());
    }
}