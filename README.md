# OpenVPN MFA Plugin
[![Build Status](https://app.travis-ci.com/SUSE/openvpn-mfa-plugin.svg?token=qTQZRsRfGWx1sh1oCwsV&branch=main)](https://app.travis-ci.com/SUSE/openvpn-mfa-plugin)

## Development
### Prerequisites
`sudo zypper in openvpn-devel`

### Build
`cargo test`

## OpenVPN Configuration
Add the following to /etc/openvpn/openvpn.conf
```
plugin /usr/lib/openvpn/plugins/libopenvpn_mfa.so --ldap ldaps://172.17.0.1:30636 --dn-totp "cn={},ou=users,ou=totp,dc=ovpn,dc=ldap,dc=suse,dc=com" --dn "cn={},ou=users,ou=cert,dc=ovpn,dc=ldap,dc=suse,dc=com"
verify-client-cert optional
username-as-common-name
```