#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConfig {
    pub log: LogConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route: RouteConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogConfig {
    pub level: String,
    pub disabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundConfig {
    Socks(SocksInboundConfig),
    Redirect(RedirectInboundConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundType {
    Socks,
    Redirect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksInboundConfig {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectInboundConfig {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
}

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
    pub tls: TrojanTlsConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanTlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub disable_sni: bool,
    pub insecure: bool,
    pub certificate_path: Option<String>,
    pub ca_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectOutboundConfig {
    pub tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteConfig {
    pub final_outbound: String,
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Socks(config) => &config.tag,
            Self::Redirect(config) => &config.tag,
        }
    }

    pub fn kind(&self) -> InboundType {
        match self {
            Self::Socks(_) => InboundType::Socks,
            Self::Redirect(_) => InboundType::Redirect,
        }
    }
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
