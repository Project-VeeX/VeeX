use super::shared::ListenFields;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundConfig {
    Direct(DirectInboundConfig),
    Socks(SocksInboundConfig),
    Redirect(RedirectInboundConfig),
    TProxy(TProxyInboundConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundType {
    Direct,
    Socks,
    Redirect,
    TProxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectInboundConfig {
    pub tag: String,
    pub listen: ListenFields,
    pub network: Option<String>,
    pub override_address: Option<String>,
    pub override_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksInboundConfig {
    pub tag: String,
    pub listen: ListenFields,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectInboundConfig {
    pub tag: String,
    pub listen: ListenFields,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TProxyInboundConfig {
    pub tag: String,
    pub listen: ListenFields,
    pub network: Option<String>,
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct(config) => &config.tag,
            Self::Socks(config) => &config.tag,
            Self::Redirect(config) => &config.tag,
            Self::TProxy(config) => &config.tag,
        }
    }

    pub fn kind(&self) -> InboundType {
        match self {
            Self::Direct(_) => InboundType::Direct,
            Self::Socks(_) => InboundType::Socks,
            Self::Redirect(_) => InboundType::Redirect,
            Self::TProxy(_) => InboundType::TProxy,
        }
    }
}
