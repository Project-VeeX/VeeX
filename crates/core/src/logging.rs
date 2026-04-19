use std::borrow::Cow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Logger {
    tag: String,
    r#type: String,
}

impl Logger {
    pub fn new(tag: impl Into<String>, r#type: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            r#type: r#type.into(),
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn type_name(&self) -> &str {
        &self.r#type
    }

    pub fn tag_field(&self) -> Cow<'_, str> {
        sanitize_field(&self.tag)
    }

    pub fn type_field(&self) -> Cow<'_, str> {
        sanitize_field(&self.r#type)
    }
}

pub fn sanitize_field(value: &str) -> Cow<'_, str> {
    if !value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Cow::Borrowed(value);
    }

    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' | '\r' => sanitized.push(' '),
            _ => sanitized.push(ch),
        }
    }

    Cow::Owned(sanitized)
}

#[cfg(test)]
mod tests {
    use super::{Logger, sanitize_field};

    #[test]
    fn leaves_plain_fields_untouched() {
        let value = sanitize_field("example.com:443");
        assert_eq!(value, "example.com:443");
    }

    #[test]
    fn replaces_line_breaks_with_spaces() {
        let value = sanitize_field("line1\r\nline2\nline3");
        assert_eq!(value, "line1  line2 line3");
    }

    #[test]
    fn logger_sanitizes_tag_and_type_fields() {
        let logger = Logger::new("socks\nin", "socks\rservice");

        assert_eq!(logger.tag_field(), "socks in");
        assert_eq!(logger.type_field(), "socks service");
    }
}
