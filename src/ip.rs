use std::net::IpAddr;
use getifs::{best_local_ipv4_addrs, best_local_ipv6_addrs};

pub trait MyIp: Sync + Send + 'static {
    fn find_my_ip(&self, client_ip: &IpAddr) -> Option<IpAddr>;
}

pub struct LocalIp {}

impl MyIp for LocalIp {
    fn find_my_ip(&self, client_ip: &IpAddr) -> Option<IpAddr> {
        match client_ip {
            IpAddr::V4(_) => {
                best_local_ipv4_addrs()
                    .map_or(None, |ips| ips.first().map(|ip| IpAddr::V4(ip.addr())))
            }
            IpAddr::V6(_) => {
                best_local_ipv6_addrs().map_or(None, |ips| ips.first().map(|ip| IpAddr::V6(ip.addr())))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use super::*;

    pub struct MockLocalIp {}

    #[cfg(test)]
    impl MyIp for MockLocalIp {
        fn find_my_ip(&self, client_ip: &IpAddr) -> Option<IpAddr> {
            if client_ip.is_ipv4() {
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            } else if client_ip.is_ipv6() {
                Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
            } else {
                None
            }
        }
    }
}
