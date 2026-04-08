use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct InputConfig {
    #[serde(default)]
    pub log: InputLogConfig,
    pub inbounds: Vec<InputInbound>,
    pub outbounds: Vec<InputOutbound>,
    pub route: InputRouteConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct InputLogConfig {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub timestamp: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum InputInboundType {
    #[serde(rename = "socks")]
    Socks,
    #[serde(rename = "redirect")]
    Redirect,
    #[serde(rename = "tproxy")]
    Tproxy,
}

#[derive(Debug, Deserialize)]
pub struct InputInbound {
    #[serde(rename = "type")]
    pub kind: InputInboundType,
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum InputOutboundType {
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "trojan")]
    Trojan,
}

#[derive(Debug, Deserialize)]
pub struct InputOutbound {
    #[serde(rename = "type")]
    pub kind: InputOutboundType,
    pub tag: String,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub server: Option<Option<String>>,
    #[serde(default)]
    pub server_port: Option<Option<u16>>,
    #[serde(default)]
    pub password: Option<Option<String>>,
    #[serde(default)]
    pub tls: Option<Option<InputTrojanTlsConfig>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct InputTrojanTlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub certificate_path: Option<String>,
    #[serde(default)]
    pub ca_path: Option<String>,
}

impl Default for InputTrojanTlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: None,
            disable_sni: false,
            insecure: false,
            certificate_path: None,
            ca_path: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InputRouteConfig {
    #[serde(rename = "final")]
    pub final_outbound: String,
    #[serde(default)]
    pub bypass: Option<Vec<String>>,
    #[serde(default)]
    pub rules: Option<Vec<InputRouteRule>>,
}

#[derive(Debug, Deserialize)]
pub struct InputRouteRule {
    #[serde(default)]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    pub domain_suffix: Option<Vec<String>>,
    #[serde(default)]
    pub ip_cidr: Option<Vec<String>>,
    #[serde(default)]
    pub port: Option<Vec<u16>>,
    #[serde(default)]
    pub inbound: Option<Vec<String>>,
    #[serde(default)]
    pub outbound: Option<Option<String>>,
}
