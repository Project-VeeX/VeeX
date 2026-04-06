//! Minimal JSON subset parser used by VeeX config loading.
//!
//! This module intentionally does not aim to be a complete general-purpose JSON implementation.
//! It supports the subset currently required by VeeX configuration:
//! objects, arrays, strings, booleans, `null`, and integer numbers.

use std::collections::BTreeMap;

use crate::error::ConfigError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

/// Parses the current VeeX configuration JSON subset.
///
/// Supported number tokens are limited to signed integers; floating-point and exponent forms are
/// rejected on purpose so configuration behavior stays explicit and easy to validate.
pub fn parse_json(input: &str) -> Result<JsonValue, ConfigError> {
    let mut parser = Parser::new(input);
    let value = parser.parse_value("$")?;
    parser.skip_whitespace();

    if !parser.is_eof() {
        return Err(ConfigError::json(
            "$",
            "trailing characters after the root JSON value",
        ));
    }

    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn parse_value(&mut self, path: &str) -> Result<JsonValue, ConfigError> {
        self.skip_whitespace();

        match self.peek() {
            Some(b'{') => self.parse_object(path),
            Some(b'[') => self.parse_array(path),
            Some(b'"') => self.parse_string(path).map(JsonValue::String),
            Some(b't') => self.parse_true(path),
            Some(b'f') => self.parse_false(path),
            Some(b'n') => self.parse_null(path),
            Some(b'-' | b'0'..=b'9') => self.parse_number(path).map(JsonValue::Number),
            Some(other) => Err(ConfigError::json(
                path,
                format!("unexpected character '{}'", other as char),
            )),
            None => Err(ConfigError::json(path, "unexpected end of input")),
        }
    }

    fn parse_object(&mut self, path: &str) -> Result<JsonValue, ConfigError> {
        self.expect_byte(b'{', path)?;
        let mut object = BTreeMap::new();
        self.skip_whitespace();

        if self.consume_if(b'}') {
            return Ok(JsonValue::Object(object));
        }

        loop {
            let key = self.parse_string(path)?;
            self.skip_whitespace();
            self.expect_byte(b':', path)?;
            let child_path = format!("{path}.{key}");
            let value = self.parse_value(&child_path)?;
            if object.contains_key(&key) {
                return Err(ConfigError::json(
                    path,
                    format!("duplicate object key `{key}` at `{child_path}`"),
                ));
            }
            object.insert(key, value);
            self.skip_whitespace();

            if self.consume_if(b'}') {
                break;
            }

            self.expect_byte(b',', path)?;
        }

        Ok(JsonValue::Object(object))
    }

    fn parse_array(&mut self, path: &str) -> Result<JsonValue, ConfigError> {
        self.expect_byte(b'[', path)?;
        let mut items = Vec::new();
        self.skip_whitespace();

        if self.consume_if(b']') {
            return Ok(JsonValue::Array(items));
        }

        let mut index = 0usize;
        loop {
            let child_path = format!("{path}[{index}]");
            items.push(self.parse_value(&child_path)?);
            index += 1;
            self.skip_whitespace();

            if self.consume_if(b']') {
                break;
            }

            self.expect_byte(b',', path)?;
        }

        Ok(JsonValue::Array(items))
    }

    fn parse_string(&mut self, path: &str) -> Result<String, ConfigError> {
        self.expect_byte(b'"', path)?;
        let mut output = String::new();
        let mut chunk_start = self.pos;

        while let Some(byte) = self.next() {
            match byte {
                b'"' => {
                    self.push_string_chunk(&mut output, chunk_start, self.pos - 1, path)?;
                    return Ok(output);
                }
                b'\\' => {
                    self.push_string_chunk(&mut output, chunk_start, self.pos - 1, path)?;
                    let escaped = self.next().ok_or_else(|| {
                        ConfigError::json(path, "unterminated escape sequence in string")
                    })?;
                    match escaped {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000C}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let code = self.parse_u16_hex(path)?;
                            let ch = char::from_u32(code as u32).ok_or_else(|| {
                                ConfigError::json(path, "invalid unicode escape sequence")
                            })?;
                            output.push(ch);
                        }
                        other => {
                            return Err(ConfigError::json(
                                path,
                                format!("unsupported escape sequence '\\{}'", other as char),
                            ));
                        }
                    }
                    chunk_start = self.pos;
                }
                0x00..=0x1F => {
                    return Err(ConfigError::json(
                        path,
                        "control characters are not allowed in strings",
                    ));
                }
                _ => {}
            }
        }

        Err(ConfigError::json(path, "unterminated string"))
    }

    fn push_string_chunk(
        &self,
        output: &mut String,
        start: usize,
        end: usize,
        path: &str,
    ) -> Result<(), ConfigError> {
        if start == end {
            return Ok(());
        }

        let chunk = std::str::from_utf8(&self.input[start..end])
            .map_err(|_| ConfigError::json(path, "string token is not valid UTF-8"))?;
        output.push_str(chunk);
        Ok(())
    }

    fn parse_number(&mut self, path: &str) -> Result<i64, ConfigError> {
        let start = self.pos;

        if self.consume_if(b'-') && !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(ConfigError::json(path, "invalid number"));
        }

        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }

        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(ConfigError::json(
                path,
                "only integer numbers are supported in the current config parser",
            ));
        }

        let slice = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ConfigError::json(path, "number token is not valid UTF-8"))?;

        slice
            .parse::<i64>()
            .map_err(|_| ConfigError::json(path, format!("invalid integer '{slice}'")))
    }

    fn parse_true(&mut self, path: &str) -> Result<JsonValue, ConfigError> {
        self.expect_keyword(b"true", path)?;
        Ok(JsonValue::Bool(true))
    }

    fn parse_false(&mut self, path: &str) -> Result<JsonValue, ConfigError> {
        self.expect_keyword(b"false", path)?;
        Ok(JsonValue::Bool(false))
    }

    fn parse_null(&mut self, path: &str) -> Result<JsonValue, ConfigError> {
        self.expect_keyword(b"null", path)?;
        Ok(JsonValue::Null)
    }

    fn parse_u16_hex(&mut self, path: &str) -> Result<u16, ConfigError> {
        let mut value = 0u16;
        for _ in 0..4 {
            let byte = self
                .next()
                .ok_or_else(|| ConfigError::json(path, "unterminated unicode escape sequence"))?;
            value = (value << 4)
                | match byte {
                    b'0'..=b'9' => (byte - b'0') as u16,
                    b'a'..=b'f' => (byte - b'a' + 10) as u16,
                    b'A'..=b'F' => (byte - b'A' + 10) as u16,
                    _ => return Err(ConfigError::json(path, "invalid unicode escape sequence")),
                };
        }
        Ok(value)
    }

    fn expect_byte(&mut self, expected: u8, path: &str) -> Result<(), ConfigError> {
        self.skip_whitespace();
        match self.next() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(ConfigError::json(
                path,
                format!(
                    "expected '{}' but found '{}'",
                    expected as char, actual as char
                ),
            )),
            None => Err(ConfigError::json(
                path,
                format!("expected '{}' but reached end of input", expected as char),
            )),
        }
    }

    fn expect_keyword(&mut self, expected: &[u8], path: &str) -> Result<(), ConfigError> {
        for byte in expected {
            match self.next() {
                Some(actual) if actual == *byte => {}
                Some(actual) => {
                    return Err(ConfigError::json(
                        path,
                        format!(
                            "expected keyword '{}' but found unexpected character '{}'",
                            String::from_utf8_lossy(expected),
                            actual as char
                        ),
                    ))
                }
                None => {
                    return Err(ConfigError::json(
                        path,
                        format!("expected keyword '{}'", String::from_utf8_lossy(expected)),
                    ))
                }
            }
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_json, JsonValue};

    #[test]
    fn parses_basic_json() {
        let json = r#"{"a":1,"b":[true,false],"c":"ok"}"#;
        let value = parse_json(json).expect("json should parse");

        match value {
            JsonValue::Object(map) => {
                assert_eq!(map.get("a"), Some(&JsonValue::Number(1)));
                assert_eq!(map.get("c"), Some(&JsonValue::String("ok".into())));
            }
            other => panic!("unexpected value: {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_object_keys_with_key_and_path() {
        let err = parse_json(
            r#"
            {
              "outbounds": [
                { "tag": "direct", "tag": "proxy" }
              ]
            }
            "#,
        )
        .expect_err("duplicate keys should fail");

        assert!(err.to_string().contains("duplicate object key `tag`"));
        assert!(err.to_string().contains("$.outbounds[0].tag"));
    }

    #[test]
    fn parses_raw_utf8_strings_without_mojibake() {
        let json = r#"{"tag":"日用"}"#;
        let value = parse_json(json).expect("json should parse");

        match value {
            JsonValue::Object(map) => {
                assert_eq!(map.get("tag"), Some(&JsonValue::String("日用".into())));
            }
            other => panic!("unexpected value: {other:?}"),
        }
    }

    #[test]
    fn parses_mixed_utf8_and_escaped_strings() {
        let json = r#"{"tag":"日用\n专线 \"香港\""}"#;
        let value = parse_json(json).expect("json should parse");

        match value {
            JsonValue::Object(map) => {
                assert_eq!(
                    map.get("tag"),
                    Some(&JsonValue::String("日用\n专线 \"香港\"".into()))
                );
            }
            other => panic!("unexpected value: {other:?}"),
        }
    }
}
