#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundMeta {
    pub tag: String,
    pub r#type: String,
}

impl InboundMeta {
    pub fn new(tag: impl Into<String>, r#type: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            r#type: r#type.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundMeta {
    pub tag: String,
    pub r#type: String,
}

impl OutboundMeta {
    pub fn new(tag: impl Into<String>, r#type: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            r#type: r#type.into(),
        }
    }
}
