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


use crate::plugin_logger::PluginLogger;
use std::ffi::{c_int};
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use log::{error, info, warn};
use base64::prelude::*;
use tokio::runtime;
use moka::sync::Cache;
use crate::config;
use crate::config::Config;
use crate::env::OpenvpnEnv;
use crate::ldap::{login, login_totp};
use crate::openvpn::{openvpn_plugin_args_func_in, openvpn_plugin_args_func_return, openvpn_plugin_args_open_in, openvpn_plugin_args_open_return, openvpn_plugin_handle_t, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, OPENVPN_PLUGIN_FUNC_DEFERRED, OPENVPN_PLUGIN_FUNC_ERROR, OPENVPN_PLUGIN_FUNC_SUCCESS};

const MODULE: &str = "openvpn-totp";

type StateId = u64;

#[derive(Eq, PartialEq, Hash)]
struct StateKey {
    username: String,
    state_id: StateId,
}

struct PluginContext {
    runtime: runtime::Runtime,
    deferred_state: Cache<StateKey, String>,
    config: Config,
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

    let mut logger = PluginLogger::new(MODULE)
        .env();

    let plugin_logger= unsafe { (*(*arguments).callbacks).plugin_log };

    logger.set_plugin_log(plugin_logger);
    logger.init().unwrap();

    let args = unsafe { config::parse_args(arguments) };
    info!("Using configuration {:?}", args);

    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_io()
        .build()
        .unwrap();

    let cache = Cache::builder()
        .time_to_live(Duration::from_secs(args.passwords_ttl))
        .max_capacity(args.passwords_max)
        .build();


    let context = Box::new(PluginContext{
        runtime,
        deferred_state: cache,
        config: args,
    });

    let retptr = unsafe { retptr.as_mut().unwrap() };
    retptr.type_mask = openvpn_plugin_mask(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    retptr.handle = Box::into_raw(context) as openvpn_plugin_handle_t;

    OPENVPN_PLUGIN_FUNC_SUCCESS as c_int
}

fn openvpn_plugin_mask(flag: u32) -> c_int {
    1<<(flag)
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

    let env = OpenvpnEnv::from_open_vpn(arguments.envp);

    if let (Some(user), Some(password)) = (*env.username(), *env.password()) {

        let Some(auth_control_file) = *env.auth_control_file() else {
            error!("Did not receive auth_control_file");
            return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
        };

        if let Some(common_name) = *env.common_name() {
            if !common_name.eq(user) {
                if let Some(auth_failed_reason_file) = env.auth_failed_reason_file() {
                    write_auth_failed_reason(auth_failed_reason_file, "CN does not match username");
                }
                return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
            }

            // Start the credentials check in the background
            login(&context.runtime, &context.config, String::from(auth_control_file), user, password);
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

                let saved_pw = context.deferred_state.remove(&state_key);

                let Some(saved_pw) = saved_pw else {
                    error!("Could not find saved_pw under state {}", &state_id);
                    return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
                };


                // Start the credentials check in the background
                login_totp(&context.runtime, &context.config, String::from(auth_control_file), user, saved_pw.as_str(), totp);

                return OPENVPN_PLUGIN_FUNC_DEFERRED as c_int;
            }

            return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
        }

        // No cert provided. Send TOTP challenge
        if let Some(auth_failed_reason_file) = env.auth_failed_reason_file() {

            let key = rand::random::<StateId>();
            let state_id = BASE64_STANDARD.encode(key.to_ne_bytes());
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
            context.deferred_state.insert(state_key, String::from(password));
            let response = format!("CRV1:R,E:{}:{}:Enter Your OTP Code", state_id, username_base64);

            write_auth_failed_reason(auth_failed_reason_file, &response);
            return OPENVPN_PLUGIN_FUNC_ERROR as c_int;
        }
    }

    OPENVPN_PLUGIN_FUNC_ERROR as c_int
}

fn write_auth_failed_reason(auth_failed_reason_file: &&str, response: &str) {
    let file = File::create(auth_failed_reason_file);

    let Ok(mut file) = file else {
        warn!("Could not open auth_failed_reason_file: {}", auth_failed_reason_file);
        return;
    };

    if let Err(err) = file.write_all(response.as_bytes()) {
        warn!("Could not write auth_failed_reason_file: {} {}", auth_failed_reason_file, err)
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