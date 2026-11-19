//! SSRF guard (SPEC R-56).
//!
//! The tool fetches URLs it found *inside* JavaScript, so a malicious script
//! could point it at `http://169.254.169.254/` or `http://localhost:6379/`.
//! Two defenses live here:
//!
//! 1. [`is_forbidden_ip`] classifies addresses we refuse to talk to.
//! 2. [`GuardedResolver`] is plugged into reqwest as its DNS resolver, so the
//!    check runs on the *resolved* addresses and the connection uses exactly
//!    the address that passed the check. Checking the hostname first and
//!    letting the HTTP client resolve again later would be vulnerable to DNS
//!    rebinding (time-of-check vs time-of-use).
//!
//! IP-literal URLs never hit the resolver, so the fetcher also calls
//! [`check_url_host`] before every hop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

/// `true` for addresses that are not publicly routable.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            // `::ffff:127.0.0.1` and friends: judge the embedded IPv4 address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_v4(v4);
            }
            is_forbidden_v6(v6)
        }
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254/16 (cloud metadata lives here)
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0                              // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xC0) == 64)   // 100.64/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
        || (o[0] == 198 && (o[1] & 0xFE) == 18)   // 198.18/15 benchmarking
        || o[0] >= 240 // 240/4 reserved
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link local
        || (seg0 == 0x2001 && ip.segments()[1] == 0x0db8) // documentation
        || ip.to_ipv4().is_some_and(is_forbidden_v4) // IPv4-compatible ::a.b.c.d
}

/// Reject IP-literal hosts that are forbidden. Hostnames are checked later by
/// [`GuardedResolver`].
pub fn check_url_host(url: &Url, allow_private: bool) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }
    let ip = match url.host() {
        Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
        Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
        Some(Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            return Err("destination `localhost` is not allowed".into());
        }
        _ => return Ok(()),
    };
    if is_forbidden_ip(ip) {
        Err(format!("destination address {ip} is not publicly routable"))
    } else {
        Ok(())
    }
}

/// A DNS resolver that drops forbidden addresses.
#[derive(Debug, Clone, Default)]
pub struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0 is a placeholder; reqwest replaces it with the URL port.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| !is_forbidden_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!(
                    "`{host}` resolves only to non-public addresses (blocked by SSRF guard; \
                     use --allow-private-targets to permit)"
                )
                .into());
            }
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forbidden_addresses() {
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_forbidden_ip(ip(bad)), "{bad} should be forbidden");
        }
    }

    #[test]
    fn public_addresses() {
        for good in ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(!is_forbidden_ip(ip(good)), "{good} should be allowed");
        }
    }

    #[test]
    fn literal_hosts() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(check_url_host(&u("http://127.0.0.1:8080/"), false).is_err());
        assert!(check_url_host(&u("http://[::1]/"), false).is_err());
        assert!(check_url_host(&u("http://localhost/"), false).is_err());
        assert!(check_url_host(&u("http://127.0.0.1/"), true).is_ok());
        assert!(check_url_host(&u("https://example.com/"), false).is_ok());
    }
}
