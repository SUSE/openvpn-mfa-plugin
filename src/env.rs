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

use std::ffi::CStr;
use std::os::raw::c_char;
use getset::Getters;
use log::debug;

#[derive(Default, Debug, Getters)]
#[getset(get = "pub")]
pub struct OpenvpnEnv<'s> {
    username: Option<&'s str>,
    password: Option<&'s str>,
    common_name: Option<&'s str>,
    auth_failed_reason_file: Option<&'s str>,
    auth_control_file: Option<&'s str>,
}

impl<'s> OpenvpnEnv<'s> {
    pub fn from_open_vpn(envp: *mut *const c_char) -> OpenvpnEnv<'s> {
        let mut i = 0;

        let mut env = OpenvpnEnv::default();

        unsafe {
            while let value = envp.add(i) && !(*value).is_null() {
                let entry = CStr::from_ptr(*value);
                env.map_env_value(entry);
                i += 1;
            }
        }

        env
    }

    fn map_env_value(&mut self, entry: &'s CStr) {
        if let Ok(value) = entry.to_str() {
            let mut split = value.splitn(2, '=');

            if let (Some(key), Some(value)) = (split.next(), split.next()) {
                debug!("ENV {} = {}", key, value);

                match key {
                    "username" => self.username = Some(value),
                    "password" => self.password = Some(value),
                    "common_name" => self.common_name = Some(value),
                    "auth_failed_reason_file" => self.auth_failed_reason_file = Some(value),
                    "auth_control_file" => self.auth_control_file = Some(value),
                    _ => ()
                }
            }
        }
    }
}