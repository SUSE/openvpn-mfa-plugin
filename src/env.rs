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
use std::net::IpAddr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str::FromStr;
use getset::Getters;
use log::debug;

#[derive(Default, Debug, Getters, Clone)]
#[getset(get = "pub")]
pub struct OpenvpnEnv {
    username: Option<String>,
    password: Option<String>,
    common_name: Option<String>,
    auth_failed_reason_file: Option<PathBuf>,
    auth_control_file: Option<PathBuf>,
    untrusted_ip: Option<IpAddr>,
    untrusted_port: Option<u16>,
}

impl<'s> OpenvpnEnv {
    pub fn from_open_vpn(envp: *mut *const c_char) -> OpenvpnEnv {
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
                    "username" => self.username = Some(String::from(value)),
                    "password" => self.password = Some(String::from(value)),
                    "common_name" => self.common_name = Some(String::from(value)),
                    "auth_failed_reason_file" => self.auth_failed_reason_file = PathBuf::from_str(value).ok(),
                    "auth_control_file" => self.auth_control_file = PathBuf::from_str(value).ok(),
                    "untrusted_ip" | "untrusted_ip6" => self.untrusted_ip = IpAddr::from_str(value).ok(),
                    "untrusted_port" => self.untrusted_port = u16::from_str(value).ok(),
                    _ => ()
                }
            }
        }
    }
}