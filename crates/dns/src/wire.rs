use veex_core::ProxyError;

pub fn parse_query_domain(message: &[u8]) -> veex_core::Result<String> {
    if message.len() < 12 {
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

    let mut offset = 12;
    let name = parse_name(message, &mut offset, 0)?;
    if offset + 4 > message.len() {
        return Err(ProxyError::protocol(
            "dns question is missing qtype or qclass",
        ));
    }

    Ok(normalize_domain(&name))
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
    use super::parse_query_domain;

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
}
