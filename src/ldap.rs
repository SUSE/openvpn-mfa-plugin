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

use ldap3::{dn_escape, LdapConnAsync, LdapConnSettings};
use log::{error, warn};
use tokio::runtime;
use crate::auth_control::{write_auth_result, AuthControl};
use crate::config;

pub fn login_totp(runtime: &runtime::Runtime, config: &config::Config, auth_control_file: String, username: &str, password: &str, totp: &str) {
    let password = format!("{};{}", password, totp);
    let dn = config.dn_totp.replacen("{}", &dn_escape(username), 1);
    check_credentials_async(runtime, config, auth_control_file, dn, password)
}

pub fn login(runtime: &runtime::Runtime, config: &config::Config, auth_control_file: String, username: &str, password: &str) {
    let dn = config.dn.replacen("{}", &dn_escape(username), 1);
    check_credentials_async(runtime, config, auth_control_file, dn, String::from(password))
}

fn check_credentials_async(runtime: &runtime::Runtime, config: &config::Config, auth_control_file: String, dn: String, password: String) {
    let url = config.ldap.clone();
    let settings = LdapConnSettings::new()
        .set_no_tls_verify(!config.tls_verify);

    runtime.spawn(async move {
        let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, url.as_str()).await {
            Ok(result) => result,
            Err(error) => {
                error!("Could not connect to ldap server: {}", error);
                write_auth_result(&auth_control_file, AuthControl::Failure);
                return;
            }
        };

        ldap3::drive!(conn);

        let result = ldap.simple_bind(dn.as_str(), password.as_str()).await;

        let outcome= match result {
            Ok(result) => {
                if result.success().is_ok() {
                    AuthControl::Success
                } else {
                    warn!("LDAP auth failure for user {}", dn);
                    AuthControl::Failure
                }
            }
            Err(error) => {
                error!("Could not bind ldap server: {}", error);
                AuthControl::Failure
            }
        };

        let _ = ldap.unbind().await;

        write_auth_result(&auth_control_file, outcome)
    });
}