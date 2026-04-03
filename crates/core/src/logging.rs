use std::borrow::Cow;

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
    use super::sanitize_field;

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
}
