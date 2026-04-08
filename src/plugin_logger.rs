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

use crate::{openvpn_plugin_log_flags_t_PLOG_DEBUG, openvpn_plugin_log_flags_t_PLOG_ERR, openvpn_plugin_log_flags_t_PLOG_NOTE, openvpn_plugin_log_flags_t_PLOG_WARN, plugin_log_t};
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::ffi::CString;
use std::str::FromStr;

pub struct PluginLogger {
    default_level: LevelFilter,
    plugin_log: Option<plugin_log_t>,
    name: CString
}

impl PluginLogger {
    #[must_use = "You must call init() to begin logging"]
    pub fn new(name: &str) -> PluginLogger {
        PluginLogger {
            default_level: LevelFilter::Trace,
            plugin_log: None,
            name: CString::new(name).unwrap()
        }
    }

    pub fn set_plugin_log(&mut self, plugin_log: plugin_log_t) {
        self.plugin_log = Some(plugin_log);
    }

    /// Enables the user to choose log level by setting `RUST_LOG=<level>`
    /// environment variable. This will use the default level set by
    /// [`with_level`] if `RUST_LOG` is not set or can't be parsed as a
    /// standard log level.
    ///
    /// This must be called after [`with_level`]. If called before
    /// [`with_level`], it will have no effect.
    ///
    /// [`with_level`]: #method.with_level
    #[must_use = "You must call init() to begin logging"]
    pub fn env(mut self) -> PluginLogger {
        self.default_level = std::env::var("RUST_LOG")
            .ok()
            .as_deref()
            .map(LevelFilter::from_str)
            .and_then(Result::ok)
            .unwrap_or(self.default_level);

        self
    }

    pub fn init(self) -> Result<(), SetLoggerError> {
        log::set_max_level(self.default_level);
        log::set_boxed_logger(Box::new(self))
    }
}

impl log::Log for PluginLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let logFn = self.plugin_log.unwrap();
            let name = self.name.as_ptr();

            let level = match record.level() {
                Level::Error => openvpn_plugin_log_flags_t_PLOG_ERR,
                Level::Warn => openvpn_plugin_log_flags_t_PLOG_WARN,
                Level::Info => openvpn_plugin_log_flags_t_PLOG_NOTE,
                Level::Debug | Level::Trace => openvpn_plugin_log_flags_t_PLOG_DEBUG,
            };

            let message = CString::new(format!("{}", record.args()));

            if let (Some(plugin_log), Ok(message)) = (logFn, message) {
                unsafe {
                    plugin_log(level, name, message.as_ptr());
                }
            } else {
                println!("FALLBACK: {} - {}", record.level(), record.args());
            }
        }
    }

    fn flush(&self) {}
}