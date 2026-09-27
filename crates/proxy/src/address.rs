use std::net::IpAddr;

#[must_use]
pub fn host_of(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((inside, _after)) => inside,
            None => rest,
        };
    }
    match address.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && is_port(port) => host,
        _ => address,
    }
}

#[must_use]
pub fn reaches_the_world(address: &str) -> bool {
    match host_of(address).parse::<IpAddr>() {
        Ok(found) => !found.is_loopback(),
        Err(_not_an_address) => true,
    }
}

fn is_port(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{host_of, reaches_the_world};

    #[test]
    fn a_host_is_taken_from_an_address_however_it_is_written() {
        assert_eq!(host_of("pg1:5432"), "pg1");
        assert_eq!(host_of("10.0.0.11:5432"), "10.0.0.11");
        assert_eq!(host_of("[::1]:5432"), "::1");
        assert_eq!(host_of("[2001:db8::7]:6432"), "2001:db8::7");
        assert_eq!(host_of("[::1]"), "::1");
        assert_eq!(host_of("::1"), "::1");
        assert_eq!(host_of("pg1"), "pg1");
        assert_eq!(host_of(""), "");
    }

    #[test]
    fn something_that_is_not_a_port_is_part_of_the_host() {
        assert_eq!(host_of("pg1:not-a-port"), "pg1:not-a-port");
        assert_eq!(host_of("pg1:"), "pg1:");
    }

    #[test]
    fn loopback_is_recognised_in_both_families() {
        assert!(!reaches_the_world("127.0.0.1:9187"));
        assert!(!reaches_the_world("127.0.0.5:9187"));
        assert!(!reaches_the_world("[::1]:9187"));
        assert!(reaches_the_world("0.0.0.0:9187"));
        assert!(reaches_the_world("[::]:9187"));
        assert!(reaches_the_world("10.0.0.4:9187"));
        assert!(
            reaches_the_world("metrics.internal:9187"),
            "a name shahrah cannot resolve is treated as reachable"
        );
    }
}
