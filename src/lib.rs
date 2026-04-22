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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs")); // TODO Move this to separate module?

mod plugin_logger;

use crate::plugin_logger::PluginLogger;
use std::ffi::{c_int, CStr};
use std::fs::File;
use std::io::Write;
use std::os::raw::c_char;
use std::time::Duration;
use log::{debug, error, warn};
use base64::prelude::*;
use ldap3::{LdapConnAsync};
use tokio::runtime;
use moka::sync::Cache;

const MODULE: &str = "openvpn-totp";

type StateId = u64;

#[derive(Eq, PartialEq, Hash)]
struct StateKey {
    username: String,
    state_id: StateId,
}

struct PluginContext {
    runtime: runtime::Runtime,
    deferredState: Cache<StateKey, String>
}

enum AuthControl {
    Success,
    Failure
}

impl AuthControl {
    fn value(&self) -> u8 {
        /*
         * first char of auth_control_file:
         * '0' -- indicates auth failure
         * '1' -- indicates auth success
         */
        match *self {
            AuthControl::Success => b'1',
            AuthControl::Failure => b'0'
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_open_v3(
    version: c_int,
    arguments: *const openvpn_plugin_args_open_in,
    retptr: *mut openvpn_plugin_args_open_return,
) -> c_int {
    if version < OPENVPN_PLUGIN_STRUCTVER_MIN {
        println!("{}: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR as c_int
    }

    let retptr = unsafe { retptr.as_mut().unwrap() };

    let mut logger = PluginLogger::new(MODULE)
        .env();

    let plugin_logger= unsafe { (*(*arguments).callbacks).plugin_log };

    logger.set_plugin_log(plugin_logger);
    logger.init().unwrap();

    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_io()
        .thread_name("openvpn-plugin-totp")
        .thread_stack_size(3 * 1024 * 1024)
        .build()
        .unwrap();

    // TODO Configurable
    let cache = Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .max_capacity(10_000)
        .build();


    let context = Box::new(PluginContext{
        runtime,
        deferredState: cache,
    });

    retptr.type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    retptr.handle = Box::into_raw(context) as openvpn_plugin_handle_t;

    OPENVPN_PLUGIN_FUNC_SUCCESS as c_int
}

fn OPENVPN_PLUGIN_MASK(flag: u32) -> c_int {
    1<<(flag)
}

#[derive(Default, Debug)]
struct OpenvpnEnv<'s> {
    username: Option<&'s str>,
    password: Option<&'s str>,
    common_name: Option<&'s str>,
    auth_failed_reason_file: Option<&'s str>,
    auth_control_file: Option<&'s str>,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_func_v3(
    version: c_int,
    arguments: *const openvpn_plugin_args_func_in,
    _retptr: *mut openvpn_plugin_args_func_return,
) -> c_int {
    if version < OPENVPN_PLUGIN_STRUCTVER_MIN {
        println!("{}: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR as c_int
    }

    let arguments = unsafe { arguments.as_ref().unwrap() };
    let context = unsafe { (arguments.handle as *mut PluginContext).as_mut().unwrap() };

    let envp = (*arguments).envp;

    let env = map_env(envp);

    if let (Some(user), Some(password)) = (env.username, env.password) {

        let Some(auth_control_file) = env.auth_control_file else {
            error!("Did not receive auth_control_file");
            return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
        };

        if let Some(common_name) = env.common_name && common_name.eq(user) {
            // Start the credentials check in the background
            check_credentials_async(&context.runtime, String::from(auth_control_file), String::from(user), String::from(password));
            return OPENVPN_PLUGIN_FUNC_DEFERRED as c_int;
        }

        // TOTP response
        if password.starts_with("CRV1:") {
            // Example: CRV1::T20wMXU3Rmg0THJHQlM3dWgwU1dtendhYlVpR2lXNmw=::123456
            let parts = password.splitn(5, ':');
            let mut parts = parts.skip(2); // CRV1 prefix & flags (empty)
            let state_id = parts.next();
            let mut parts = parts.skip(1);
            let totp = parts.next();

            if let (Some(state_id), Some(totp)) = (state_id, totp) {
                let Ok(state) = BASE64_STANDARD.decode(state_id) else {
                    error!("Could not decode state {}", state_id);
                    return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
                };

                let Some((int_bytes, _)) = state.split_at_checked(size_of::<StateId>()) else {
                    error!("Could not decode state {}", state_id);
                    return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
                };

                let Ok(int_bytes): Result<[u8;size_of::<u64>()], _> = int_bytes.try_into() else {
                    error!("Could not decode state {}", state_id);
                    return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
                };

                let state_key = StateKey {
                    username: user.to_string(),
                    state_id: StateId::from_ne_bytes(int_bytes),
                };

                let saved_pw = context.deferredState.remove(&state_key);

                let Some(saved_pw) = saved_pw else {
                    error!("Could not find saved_pw under state {}", &state_id);
                    return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
                };

                let password = format!("{};{}", saved_pw, totp);
                // Start the credentials check in the background
                check_credentials_async(&context.runtime, String::from(auth_control_file), String::from(user), password);

                return OPENVPN_PLUGIN_FUNC_DEFERRED as c_int;
            }

            return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
        }

        // No cert provided. Send TOTP challenge
        if let Some(auth_failed_reason_file) = env.auth_failed_reason_file {
            let file = File::create(auth_failed_reason_file);

            let Ok(mut file) = file else {
                warn!("Could not open auth_failed_reason_file: {}", auth_failed_reason_file);
                return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
            };

            let key = rand::random::<StateId>();
            let state_id = BASE64_STANDARD.encode(&key.to_ne_bytes());
            let username_base64 = BASE64_STANDARD.encode(user);

            /*
             Can't store the password in per_client_context because the client actually disconnects and
             thus has a new context on the TOTP reconnect.

             -> Store in global context.
             */
            let state_key = StateKey {
                username: user.to_string(),
                state_id: key,
            };
            context.deferredState.insert(state_key, String::from(password));

            let response = format!("CRV1:R,E:{}:{}:Enter Your OTP Code", state_id, username_base64);
            if let Err(err) = file.write_all(response.as_bytes()) {
                warn!("Could not write auth_failed_reason_file: {} {}", auth_failed_reason_file, err);
                return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
            }

            return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
        }
    }

    OPENVPN_PLUGIN_FUNC_ERROR as c_int
}

fn check_credentials_async(runtime: &runtime::Runtime, auth_control_file: String, username: String, password: String) -> () {
    runtime.spawn(async move {

        let Ok((conn, mut ldap)) = LdapConnAsync::new("TODO").await else {
            error!("Could not connect to ldap server");
            write_auth_result(&auth_control_file, AuthControl::Failure);
            return;
        };

        ldap3::drive!(conn);

        let dn = format!("uid={},dc=example,dc=com", username);
        let result = ldap.simple_bind(dn.as_str(), password.as_str()).await;

        let outcome;
        if let Err(e) = result {
            error!("Could not bind ldap server: {}", e);
            outcome = AuthControl::Failure;
        } else {

            if let Ok(_) = result.unwrap().success() {
                outcome = AuthControl::Success;
            } else {
                outcome = AuthControl::Failure;
                warn!("LDAP auth failure for user {}", username);
            }
        }

        let _ = ldap.unbind().await;

        write_auth_result(&auth_control_file, outcome)
    });
}

fn write_auth_result(auth_control_file: &String, outcome: AuthControl) {
    let file = File::create(&auth_control_file);
    let Ok(mut file) = file else {
        warn!("Could not open auth_control_file: {}", auth_control_file);
        return;
    };

    if let Err(err) = file.write_all(&[outcome.value()]) {
        warn!("Could not write auth_control_file: {} {}", auth_control_file, err);
        return;
    }
}

fn map_env<'a>(envp: *mut *const c_char) -> OpenvpnEnv<'a> {
    let mut i = 0;

    let mut env = OpenvpnEnv::default();

    unsafe {
        while let value = envp.add(i) && !(*value).is_null() {
            let entry = CStr::from_ptr(*value);
            map_env_value(&mut env, entry);
            i += 1;
        }
    }

    env
}

fn map_env_value<'a>(env: &mut OpenvpnEnv<'a>, entry: &'a CStr) {
    if let Ok(value) = entry.to_str() {
        let mut split = value.splitn(2, '=');

        if let (Some(key), Some(value)) = (split.next(), split.next()) {
            debug!("ENV {} = {}", key, value);

            match key {
                "username" => env.username = Some(value),
                "password" => env.password = Some(value),
                "common_name" => env.common_name = Some(value),
                "auth_failed_reason_file" => env.auth_failed_reason_file = Some(value),
                "auth_control_file" => env.auth_control_file = Some(value),
                _ => ()
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_close_v1(handle: openvpn_plugin_handle_t) {
    assert!(!handle.is_null());

    // https://stackoverflow.com/a/46677043
    let context = unsafe { Box::from_raw(handle as *mut PluginContext) }; // Rust auto-drops it
    context.runtime.shutdown_timeout(Duration::from_mins(1));
}

const OPENVPN_PLUGIN_VERSION_MIN: c_int = 3;
const OPENVPN_PLUGIN_STRUCTVER_MIN: c_int = 5;

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_min_version_required_v1() -> c_int {
    OPENVPN_PLUGIN_VERSION_MIN
}