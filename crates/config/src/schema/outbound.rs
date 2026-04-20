use super::shared::{DialFields, TlsFields};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConfig {
    Trojan(TrojanOutboundConfig),
    Direct(DirectOutboundConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundType {
    Trojan,
    Direct,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanOutboundConfig {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub dial: DialFields,
    pub tls: TlsFields,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectOutboundConfig {
    pub tag: String,
    pub dial: DialFields,
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Trojan(config) => &config.tag,
            Self::Direct(config) => &config.tag,
        }
    }

    pub fn kind(&self) -> OutboundType {
        match self {
            Self::Trojan(_) => OutboundType::Trojan,
            Self::Direct(_) => OutboundType::Direct,
        }
    }
}
