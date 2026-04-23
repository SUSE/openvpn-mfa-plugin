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
use clap::Parser;
use crate::openvpn::openvpn_plugin_args_open_in;

#[derive(Parser, Debug)]
#[command()]
pub struct Config {
    /// Connection url for LDAP server
    #[arg(short, long)]
    pub ldap: String,

    /// Verify tls on ldap server
    #[arg(long, default_value_t = true)]
    pub tls_verify: bool,

    /// Dn used for totp based authentication
    #[arg(long)]
    pub dn_totp: String,

    /// Dn used for auth without totp
    #[arg(short, long)]
    pub dn: String,

    /// Number of threads for the async runtime
    #[arg(long, default_value_t = 1)]
    pub threads: usize,

    /// Max amount of passwords in memory
    #[arg(long, default_value_t = 10_000)]
    pub passwords_max: u64,

    /// Max duration in seconds the passwords are kept in memory for the totp roundtrip.
    #[arg(long, default_value_t = 60)]
    pub passwords_ttl: u64,
}

pub unsafe fn parse_args(arguments: *const openvpn_plugin_args_open_in) -> Config {
    let mut args = vec![];
    unsafe {
        let argv = (*arguments).argv;
        let mut i = 0;
        while let value = argv.add(i) && !(*value).is_null() {
            let entry = CStr::from_ptr(*value).to_string_lossy().into_owned();
            i += 1;
            args.push(entry)
        }
    }

    Config::parse_from(args)
}