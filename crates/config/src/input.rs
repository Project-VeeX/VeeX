use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Deserializer};
use serde_json::Value;

fn default_true() -> bool {
    true
}

fn deserialize_optional_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            humantime::parse_duration(&value).map_err(|_| {
                serde::de::Error::custom("invalid duration, expected formats like 300ms, 5s, 2m")
            })
        })
        .transpose()
}

fn deserialize_optional_string_list_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringListOrString {
        List(Vec<String>),
        Single(String),
    }

    Ok(
        Option::<StringListOrString>::deserialize(deserializer)?.map(|value| match value {
            StringListOrString::List(values) => values,
            StringListOrString::Single(value) => vec![value],
        }),
    )
}

#[derive(Debug, Deserialize)]
pub struct InputConfig {
    #[serde(default)]
    pub log: InputLogConfig,
    #[serde(default)]
    pub dns: Option<InputDnsConfig>,
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
    #[serde(rename = "direct")]
    Direct,
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
    #[serde(default)]
    pub override_address: Option<String>,
    #[serde(default)]
    pub override_port: Option<u16>,
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
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub connect_timeout: Option<Duration>,
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
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub handshake_timeout: Option<Duration>,
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
            handshake_timeout: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InputRouteConfig {
    #[serde(rename = "final")]
    pub final_outbound: String,
    #[serde(default)]
    pub rules: Option<Vec<InputRouteRule>>,
}

#[derive(Debug, Deserialize)]
pub struct InputRouteRule {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_list_or_string"
    )]
    pub domain: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_list_or_string"
    )]
    pub domain_suffix: Option<Vec<String>>,
    #[serde(default)]
    pub ip_cidr: Option<Vec<String>>,
    #[serde(default)]
    pub ip_is_private: bool,
    #[serde(default)]
    pub ip_is_loopback: bool,
    #[serde(default)]
    pub ip_is_link_local: bool,
    #[serde(default)]
    pub port: Option<Vec<u16>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_list_or_string"
    )]
    pub inbound: Option<Vec<String>>,
    #[serde(default)]
    pub outbound: Option<Option<String>>,
    #[serde(default)]
    pub action: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub timeout: Option<Duration>,
}

#[derive(Debug, Deserialize)]
pub struct InputDnsConfig {
    #[serde(rename = "final", default)]
    pub final_server: Option<Option<String>>,
    pub servers: Vec<InputDnsServer>,
    #[serde(default)]
    pub rules: Option<Vec<InputDnsRule>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct InputDnsServer {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub server: Option<Option<String>>,
    #[serde(default)]
    pub server_port: Option<Option<u16>>,
    #[serde(default)]
    pub path: Option<Option<String>>,
    #[serde(default)]
    pub headers: Option<Option<BTreeMap<String, String>>>,
    #[serde(default)]
    pub detour: Option<Option<String>>,
    #[serde(default)]
    pub tls: Option<Option<InputTrojanTlsConfig>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct InputDnsRule {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_list_or_string"
    )]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    pub server: Option<Option<String>>,
    #[serde(default)]
    pub action: Option<Option<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
