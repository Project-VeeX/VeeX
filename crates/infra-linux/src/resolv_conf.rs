use std::{fs, io, net::IpAddr};

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

pub fn load_system_dns_servers() -> io::Result<Vec<IpAddr>> {
    let contents = fs::read_to_string(RESOLV_CONF_PATH)?;
    Ok(parse_resolv_conf_nameservers(&contents))
}

fn parse_resolv_conf_nameservers(contents: &str) -> Vec<IpAddr> {
    contents.lines().filter_map(parse_nameserver_line).collect()
}

fn parse_nameserver_line(line: &str) -> Option<IpAddr> {
    let line = strip_inline_comment(line).trim();
    if line.is_empty() {
        return None;
    }

    let mut parts = line.split_whitespace();
    let key = parts.next()?;
    if key != "nameserver" {
        return None;
    }

    let value = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    value.parse().ok()
}

fn strip_inline_comment(line: &str) -> &str {
    let mut comment_start = line.len();
    for marker in ['#', ';'] {
        if let Some(index) = line.find(marker) {
            comment_start = comment_start.min(index);
        }
    }
    &line[..comment_start]
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::parse_resolv_conf_nameservers;

    #[test]
    fn extracts_only_nameserver_ip_addresses() {
        let nameservers = parse_resolv_conf_nameservers(
            r#"
            # comment
            search lan
            nameserver 1.1.1.1
            nameserver 2606:4700:4700::1111
            options ndots:5
            nameserver invalid
            nameserver 8.8.8.8 extra
            nameserver 9.9.9.9 # inline comment
            "#,
        );

        assert_eq!(
            nameservers,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            ]
        );
    }

    #[test]
    fn ignores_non_nameserver_lines_and_blank_input() {
        let nameservers = parse_resolv_conf_nameservers(
            r#"
            domain example.test
            sortlist 10.0.0.0/8
            "#,
        );

        assert!(nameservers.is_empty());
    }
}
