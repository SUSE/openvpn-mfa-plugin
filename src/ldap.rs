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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use ldap3::{dn_escape, Ldap, LdapConnAsync, LdapConnSettings, StdStream};
use log::{error, warn};
use tokio::net::TcpStream;
use tokio::{runtime, time};
use crate::auth_control::{write_auth_result, AuthControl};
use url::Url;
use proxy_protocol_rs::HeaderBuilder;
use anyhow::Context;
use crate::config::Config;
use crate::ip::{LocalIp, MyIp};

pub struct LdapClient {
    runtime: runtime::Runtime,
    pub ip_resolver: Arc<dyn MyIp>,
    config: Arc<Config>,
}

pub struct LdapRequest {
    pub ip_resolver: Arc<dyn MyIp>,
    config: Arc<Config>,

}

impl LdapRequest {

    async fn check_credentials_async(&self, client: &SocketAddr, auth_control_file: &Path, dn: String, password: String) {
        let outcome = self._check_credentials(client, dn, password).await;
        write_auth_result(auth_control_file, outcome)
    }

    async fn connect(&self,client: &SocketAddr) -> anyhow::Result<(LdapConnAsync, Ldap)> {
        let url = Url::parse(&self.config.ldap).context("failed to parse url")?;
        let addrs = url.socket_addrs(|| None).context("failed to resolve url")?;
        let timeout = time::timeout(Duration::from_secs(1), TcpStream::connect(&addrs[0])).await;

        let mut tokio_stream = timeout.context("Timeout")?.context("tcp error")?;

        // We don't get any information from OpenVPN about which ip:port pair the client connected to.
        // So the idea is to just take any of our local ips and hardcode the standard port.
        // Not perfect but better than nothing.
        if self.config.forward_ip {
            let Some(server_ip) = (*self.ip_resolver.as_ref()).find_my_ip(&client.ip()) else {
                // Configuration error? Happens when the client IP is IPv6 but the server doesn't have an IPv6 address.
                return Err(anyhow::anyhow!("Could not find local IP for: {}", client.ip()));
            };

            let server = SocketAddr::new(server_ip, 1194);

            HeaderBuilder::v2_proxy(
                *client,
                server,
            ).write_to(&mut tokio_stream).await?;
        }

        let std_stream = tokio_stream.into_std()?;

        let settings = LdapConnSettings::new()
            .set_no_tls_verify(self.config.skip_tls_verify)
            .set_std_stream(StdStream::Tcp(std_stream));

        LdapConnAsync::with_settings(settings, url.as_str()).await.context("Ldap connection failed")
    }

    async fn _check_credentials(&self, client: &SocketAddr, dn: String, password: String) -> AuthControl {
        let (conn, mut ldap) = match self.connect(client).await {
            Ok(x) => x,
            Err(e) => {
                warn!("LDAP auth failure for user {} {}", dn, e);
                return AuthControl::Failure;
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

        if let Err(error) = ldap.unbind().await {
            error!("Could not unbind ldap server: {}", error);
        }

        outcome
    }
}

impl LdapClient {

    pub fn new(runtime: runtime::Runtime, config: Arc<Config>) -> Self {
        LdapClient {
            ip_resolver: Arc::new(LocalIp {}),
            runtime,
            config,
        }
    }

    pub fn shutdown_timeout(self, duration: Duration) {
        self.runtime.shutdown_timeout(duration);
    }

    pub fn login_totp(&self, client: &SocketAddr, auth_control_file: &Path, username: &str, password: &str, totp: &str) {
        let dn_totp = self.config.dn_totp.as_ref().expect("login_totp requires dn_totp");
        let password = format!("{};{}", password, totp);
        let dn = dn_totp.replacen("{}", &dn_escape(username), 1);
        let client = *client;
        let auth_control_file = PathBuf::from(auth_control_file);
        let ldap_request = LdapRequest{ip_resolver: Arc::clone(&self.ip_resolver), config: self.config.clone(), };

        self.runtime.spawn(async move {
            ldap_request.check_credentials_async(&client, auth_control_file.as_path(), dn, password).await;
        });
    }

    pub fn login(&self, client: &SocketAddr, auth_control_file: &Path, username: &str, password: &str) {
        let dn = self.config.dn.replacen("{}", &dn_escape(username), 1);
        let password = String::from(password);
        let client = *client;
        let auth_control_file = PathBuf::from(auth_control_file);
        let ldap_request = LdapRequest{ip_resolver: Arc::clone(&self.ip_resolver), config: self.config.clone(), };

        self.runtime.spawn(async move {
            ldap_request.check_credentials_async(&client, auth_control_file.as_path(), dn, password).await;
        });
    }




}
#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::IpAddr;
    use testcontainers::{core::{IntoContainerPort, WaitFor}, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt};
    use testcontainers::core::{CmdWaitFor, ExecCommand};
    use testcontainers::core::wait::LogWaitStrategy;
    use tempfile::NamedTempFile;
    use testcontainers::core::logs::consumer::logging_consumer::LoggingConsumer;
    use tracing::info;
    use tracing_test::traced_test;
    use crate::ip::tests::MockLocalIp;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[traced_test]
    async fn ldap_connect_with_proxy_ipv4() {
        ldap_connect_with_proxy("10.1.2.3").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[traced_test]
    async fn ldap_connect_with_proxy_ipv6() {
        ldap_connect_with_proxy("fd11:2222:3333::1").await;
    }

    async fn ldap_connect_with_proxy(source: &str) {

        info!("Creating 389-ds container");
        let ldap = ldap_container().await;

        let host = match ldap.get_bridge_ip_address().await.unwrap() {
            IpAddr::V4(addr) => addr.to_string(),
            IpAddr::V6(addr) => addr.to_string()
        };
        info!("ldap host found: {}", host);

        info!("Creating haproxy container");
        let haproxy = haproxy_container(&host).await;
        let host = haproxy.get_bridge_ip_address().await.unwrap();
        info!("Haproxy host found: {}", host);



        info!("Running test");
        let haproxy_port = haproxy.get_host_port_ipv4(6379.tcp()).await.unwrap();
        let config = Config {
            ldap: format!("ldap://127.0.0.1:{}", haproxy_port),
            forward_ip: true,
            ..Default::default()
        };

        // Ensure that tcp port is ready
        let socket_addr = format!("127.0.0.1:{}", haproxy_port).parse().unwrap();
        time::timeout(Duration::from_secs(10), wait_for_port(socket_addr)).await.unwrap();

        let auth_control_file = NamedTempFile::new().unwrap();
        let client = SocketAddr::new(source.parse().unwrap(), 1194);

        let ldap_request = LdapRequest{ip_resolver: Arc::from(MockLocalIp{}), config: Arc::new(config)};

        ldap_request.check_credentials_async(&client, auth_control_file.path(), String::from("uid=ldap_user,ou=people,dc=suse,dc=com"), String::from("changeme")).await;

        let contents = fs::read_to_string(auth_control_file)
            .expect("Should have been able to read the file");

        assert_eq!(contents, String::from_utf8(vec![AuthControl::Success.value()]).unwrap());

        let access_log = ldap.copy_file_from("/data/logs/access", Vec::new()).await.unwrap();
        let access_log = String::from_utf8(access_log).unwrap();

        // Check that 389-ds sees the correct source ip
        assert!(access_log.contains(format!("HAProxy new_address_from={}", source).as_str()));
    }

    async fn haproxy_container(ip: &str) -> ContainerAsync<GenericImage> {
        let mut config = fs::read_to_string("tests/fixtures/assets/haproxy.cfg").unwrap();
        config = config.replace("__IP__", ip);

        GenericImage::new("haproxy", "2.3")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::Log(LogWaitStrategy::stdout_or_stderr("New worker")))
            .with_copy_to("/usr/local/etc/haproxy/haproxy.cfg", config.as_bytes().to_vec())
            .with_log_consumer(LoggingConsumer::default().with_prefix("[HAPROXY]"))
            .start()
            .await.unwrap()
    }

    async fn ldap_container() -> ContainerAsync<GenericImage> {
        let ldap = GenericImage::new("registry.suse.com/suse/389-ds", "3.0")
            .with_exposed_port(3389.tcp())
            .with_exposed_port(3636.tcp())
            .with_wait_for(WaitFor::Log(LogWaitStrategy::stdout("INFO: 389-ds-container started")))
            .with_env_var("DS_DM_PASSWORD", "changeme")
            .with_hostname("ldap")
            .with_log_consumer(LoggingConsumer::default().with_prefix("[LDAP]"))
            .start()
            .await.unwrap();

        info!("Creating ldap backend");
        let command = ExecCommand::new(vec!["dsconf", "localhost", "backend", "create", "--suffix", "dc=suse,dc=com", "--be-name", "userroot", "--create-suffix", "--create-entries"])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0));
        ldap.exec(command).await.unwrap();

        // Both the server ip and the proxy ip must be in the whitelist: https://github.com/389ds/389-ds-base/blob/b885a34a79aeeb18ad7792da1a29cb83d0f3268c/ldap/servers/slapd/connection.c#L1326
        let command = ExecCommand::new(vec!["dsconf", "localhost", "config", "replace", "nsslapd-haproxy-trusted-ip=0.0.0.0/0", "nsslapd-haproxy-trusted-ip=::/0"])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0));
        ldap.exec(command).await.unwrap();

        // Disable access log buffering so we can read it back at the end of the test.
        let command = ExecCommand::new(vec!["dsconf", "localhost", "config", "replace", "nsslapd-accesslog-logbuffering=off"])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0));
        ldap.exec(command).await.unwrap();


        info!("Creating ldap user");
        let command = ExecCommand::new(vec!["dsidm", "localhost", "--basedn", "dc=suse,dc=com", "user", "create",
                                            "--uid", "ldap_user", "--cn", "ldap_user", "--displayName", "ldap_user", "--uidNumber", "1001", "--gidNumber", "1001", "--homeDirectory", "/home/ldap_user"
        ])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0));
        ldap.exec(command).await.unwrap();

        info!("Creating ldap user password hash");
        let command = ExecCommand::new(vec!["pwdhash", "-D", "/etc/dirsrv/slapd-localhost", "changeme"])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0));
        let mut cmd = ldap.exec(command).await.unwrap();
        let password_hash = cmd.stdout_to_vec().await.unwrap();
        let password_hash = String::from_utf8(password_hash).unwrap();

        info!("Setting ldap user password");
        let command = ExecCommand::new(vec!["dsidm", "localhost", "--basedn", "dc=suse,dc=com", "user", "modify", "ldap_user", format!("add:userPassword:{}", password_hash.trim()).as_str()])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0));
        ldap.exec(command).await.unwrap();
        ldap
    }

    async fn wait_for_port(socket_addr: SocketAddr) {
        loop {
            let timeout = time::timeout(Duration::from_millis(100), TcpStream::connect(socket_addr)).await;

            if let Ok(Ok(mut tokio_stream)) = timeout {
                let server = SocketAddr::new("10.0.0.100".parse().unwrap(), 1194);
                let client = SocketAddr::new("10.0.0.102".parse().unwrap(), 1194);

                let result = HeaderBuilder::v2_proxy(
                    client,
                    server,
                ).write_to(&mut tokio_stream).await;

                if result.is_ok() {
                    info!("Done waiting for port. Success.");
                    return;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}