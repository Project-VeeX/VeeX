use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use veex_core::ProxyError;

const DNS_HEADER_LEN: usize = 12;
const DNS_FLAG_RESPONSE: u8 = 0x80;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQueryInfo {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
}

pub fn parse_query_domain(message: &[u8]) -> veex_core::Result<String> {
    Ok(parse_query_info(message)?.name)
}

pub fn parse_query_info(message: &[u8]) -> veex_core::Result<DnsQueryInfo> {
    if message.len() < DNS_HEADER_LEN {
        return Err(ProxyError::protocol(
            "dns message is shorter than the header",
        ));
    }

    let question_count = u16::from_be_bytes([message[4], message[5]]);
    if question_count == 0 {
        return Err(ProxyError::protocol(
            "dns query must contain at least one question",
        ));
    }

    let mut offset = DNS_HEADER_LEN;
    let name = parse_name(message, &mut offset, 0)?;
    if offset + 4 > message.len() {
        return Err(ProxyError::protocol(
            "dns question is missing qtype or qclass",
        ));
    }

    Ok(DnsQueryInfo {
        id: u16::from_be_bytes([message[0], message[1]]),
        name: normalize_domain(&name),
        qtype: u16::from_be_bytes([message[offset], message[offset + 1]]),
    })
}

pub fn build_a_query(domain: &str, query_id: u16) -> veex_core::Result<Vec<u8>> {
    let normalized = normalize_domain(domain);
    if normalized.is_empty() {
        return Err(ProxyError::protocol("dns query domain must not be empty"));
    }

    let mut query = Vec::with_capacity(DNS_HEADER_LEN + normalized.len() + 6);
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ProxyError::protocol("dns label length is invalid"));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    Ok(query)
}

pub fn parse_response_ips(message: &[u8]) -> veex_core::Result<Vec<IpAddr>> {
    if message.len() < DNS_HEADER_LEN {
        return Err(ProxyError::protocol(
            "dns response is shorter than the header",
        ));
    }

    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        parse_name(message, &mut offset, 0)?;
        if offset + 4 > message.len() {
            return Err(ProxyError::protocol("dns question is truncated"));
        }
        offset += 4;
    }

    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        parse_name(message, &mut offset, 0)?;
        if offset + 10 > message.len() {
            return Err(ProxyError::protocol("dns answer header is truncated"));
        }

        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let record_class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        offset += 8; // type + class + ttl
        let data_length = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        let data = message
            .get(offset..offset + data_length)
            .ok_or_else(|| ProxyError::protocol("dns answer data is truncated"))?;

        if record_class == DNS_CLASS_IN {
            match record_type {
                DNS_TYPE_A if data_length == 4 => {
                    addresses.push(IpAddr::V4(Ipv4Addr::new(
                        data[0], data[1], data[2], data[3],
                    )));
                }
                DNS_TYPE_AAAA if data_length == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(data);
                    addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }

        offset += data_length;
    }

    if addresses.is_empty() {
        return Err(ProxyError::resolve(
            "dns response did not contain usable A/AAAA answers",
        ));
    }

    Ok(addresses)
}

pub fn parse_response_min_ttl(
    message: &[u8],
    query_type: u16,
) -> veex_core::Result<Option<Duration>> {
    if message.len() < DNS_HEADER_LEN {
        return Err(ProxyError::protocol(
            "dns response is shorter than the header",
        ));
    }

    if (message[2] & DNS_FLAG_RESPONSE) == 0 {
        return Err(ProxyError::protocol("dns message is not a response"));
    }

    let rcode = message[3] & 0x0f;
    if rcode != 0 {
        return Ok(None);
    }

    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        parse_name(message, &mut offset, 0)?;
        if offset + 4 > message.len() {
            return Err(ProxyError::protocol("dns question is truncated"));
        }
        offset += 4;
    }

    let mut min_ttl: Option<u32> = None;
    for _ in 0..answer_count {
        parse_name(message, &mut offset, 0)?;
        if offset + 10 > message.len() {
            return Err(ProxyError::protocol("dns answer header is truncated"));
        }

        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let record_class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let ttl = u32::from_be_bytes([
            message[offset + 4],
            message[offset + 5],
            message[offset + 6],
            message[offset + 7],
        ]);
        let data_length = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        let data_end = offset + data_length;
        if data_end > message.len() {
            return Err(ProxyError::protocol("dns answer data is truncated"));
        }

        if record_class == DNS_CLASS_IN && record_type == query_type && ttl > 0 {
            min_ttl = Some(match min_ttl {
                Some(existing) => existing.min(ttl),
                None => ttl,
            });
        }

        offset = data_end;
    }

    Ok(min_ttl.map(|ttl| Duration::from_secs(ttl as u64)))
}

pub fn rewrite_message_id(message: &[u8], query_id: u16) -> veex_core::Result<Vec<u8>> {
    if message.len() < 2 {
        return Err(ProxyError::protocol(
            "dns message is shorter than the transaction id",
        ));
    }

    let mut rewritten = message.to_vec();
    rewritten[..2].copy_from_slice(&query_id.to_be_bytes());
    Ok(rewritten)
}

fn parse_name(message: &[u8], offset: &mut usize, depth: u8) -> veex_core::Result<String> {
    if depth > 8 {
        return Err(ProxyError::protocol("dns name compression depth exceeded"));
    }

    let mut labels = Vec::new();
    let mut cursor = *offset;
    loop {
        let Some(&len) = message.get(cursor) else {
            return Err(ProxyError::protocol("dns name truncated"));
        };

        if len == 0 {
            cursor += 1;
            *offset = cursor;
            break;
        }

        if (len & 0b1100_0000) == 0b1100_0000 {
            let Some(&next) = message.get(cursor + 1) else {
                return Err(ProxyError::protocol("dns compression pointer truncated"));
            };
            let pointer = (((len as usize) & 0b0011_1111) << 8) | next as usize;
            if pointer >= message.len() {
                return Err(ProxyError::protocol("dns compression pointer out of range"));
            }
            *offset = cursor + 2;
            let mut nested = pointer;
            let nested_name = parse_name(message, &mut nested, depth + 1)?;
            if !nested_name.is_empty() {
                labels.push(nested_name);
            }
            break;
        }

        let label_len = len as usize;
        let start = cursor + 1;
        let end = start + label_len;
        let label = message
            .get(start..end)
            .ok_or_else(|| ProxyError::protocol("dns label truncated"))?;
        let label = std::str::from_utf8(label)
            .map_err(|_| ProxyError::protocol("dns label is not valid utf-8"))?;
        labels.push(label.to_string());
        cursor = end;
    }

    Ok(labels.join("."))
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use super::{
        DNS_TYPE_A, build_a_query, parse_query_domain, parse_query_info, parse_response_ips,
        parse_response_min_ttl, rewrite_message_id,
    };

    #[test]
    fn parses_single_question_query_name() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let domain = parse_query_domain(&query).expect("query domain should parse");
        assert_eq!(domain, "www.example.com");
    }

    #[test]
    fn builds_a_query_with_requested_domain() {
        let query = build_a_query("Example.COM", 0x1234).expect("query should build");
        assert_eq!(
            parse_query_domain(&query).expect("query domain should parse"),
            "example.com"
        );
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(
            parse_query_info(&query)
                .expect("query info should parse")
                .qtype,
            DNS_TYPE_A
        );
    }

    #[test]
    fn parses_ipv4_answers_from_response() {
        let query = build_a_query("example.com", 0x1234).expect("query should build");
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[203, 0, 113, 5]);

        let addresses = parse_response_ips(&response).expect("response should parse");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))]);
        assert_eq!(
            parse_response_min_ttl(&response, DNS_TYPE_A).expect("ttl should parse"),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn rewrite_message_id_updates_transaction_id_only() {
        let query = build_a_query("example.com", 0x1234).expect("query should build");
        let rewritten = rewrite_message_id(&query, 0xbeef).expect("query id should rewrite");

        assert_eq!(&rewritten[..2], &[0xbe, 0xef]);
        assert_eq!(&rewritten[2..], &query[2..]);
    }
}
