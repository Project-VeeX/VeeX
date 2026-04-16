use std::time::Duration;

use ipnet::IpNet;
use tracing::{debug, info, warn};

use crate::{
    io::{BoxedAsyncStream, PacketCarrier, StreamCarrier},
    logging::sanitize_field,
    session::SessionContext,
    types::{Destination, Host},
};

use super::{sniff_stream_internal, RouteError, RouteResult, SniffExecution, SniffResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteReason {
    Rule,
    Final,
}

impl RouteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Final => "final",
        }
    }
}

/// The result of a routing decision for a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    /// Final action selected to handle this session.
    pub final_action: RouteFinalAction,
    /// Reason for the routing decision.
    pub reason: RouteReason,
}

impl RouteDecision {
    pub fn route(outbound_tag: impl Into<String>, reason: RouteReason) -> Self {
        Self {
            final_action: RouteFinalAction::Route(RouteTarget::new(outbound_tag)),
            reason,
        }
    }

    pub fn route_target(&self) -> Option<&RouteTarget> {
        match &self.final_action {
            RouteFinalAction::Route(target) => Some(target),
            RouteFinalAction::HijackDns => None,
        }
    }

    pub fn outbound_tag(&self) -> Option<&str> {
        self.route_target()
            .map(|target| target.outbound_tag.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteAction {
    Upgrade(RouteUpgradeAction),
    Final(RouteFinalAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteUpgradeAction {
    Sniff(SniffAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SniffAction {
    pub timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteFinalAction {
    Route(RouteTarget),
    HijackDns,
    // Future terminal actions such as reject / bypass would extend this enum here.
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTarget {
    pub outbound_tag: String,
}

impl RouteTarget {
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            outbound_tag: outbound_tag.into(),
        }
    }
}

/// Minimal route rule shape supported by the current router.
///
/// All populated matcher fields must match (`AND` semantics).
/// Rules are evaluated in declaration order and execute either an upgrade action
/// or a final action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRule {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
    pub ip_is_private: bool,
    pub ip_is_loopback: bool,
    pub ip_is_link_local: bool,
    pub port: Vec<u16>,
    pub inbound: Vec<String>,
    pub action: RouteAction,
}

impl RouteRule {
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: Vec::new(),
            ip_cidr: Vec::new(),
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: Vec::new(),
            inbound: Vec::new(),
            action: RouteAction::Final(RouteFinalAction::Route(RouteTarget::new(outbound_tag))),
        }
    }

    pub fn sniff(timeout: Duration) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: Vec::new(),
            ip_cidr: Vec::new(),
            ip_is_private: false,
            ip_is_loopback: false,
            ip_is_link_local: false,
            port: Vec::new(),
            inbound: Vec::new(),
            action: RouteAction::Upgrade(RouteUpgradeAction::Sniff(SniffAction { timeout })),
        }
    }
}

/// Minimal routing input shape used by the pure router.
///
/// `domain` is separate from `destination.host` so the router can be rerun
/// after a sniff phase provides richer metadata for an IP destination.
#[derive(Clone, Copy, Debug)]
pub struct RouteInput<'a> {
    pub destination: &'a Destination,
    pub inbound_tag: Option<&'a str>,
    pub domain: Option<&'a str>,
}

impl<'a> RouteInput<'a> {
    pub fn new(
        destination: &'a Destination,
        inbound_tag: Option<&'a str>,
        domain: Option<&'a str>,
    ) -> Self {
        Self {
            destination,
            inbound_tag,
            domain,
        }
    }

    pub fn from_session(ctx: &'a SessionContext) -> Self {
        Self {
            destination: &ctx.meta.destination,
            inbound_tag: Some(ctx.meta.inbound_tag.as_str()),
            domain: ctx.meta.destination.host.as_domain(),
        }
    }

    fn host(self) -> &'a Host {
        &self.destination.host
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RouteRuntimeContext {
    domain: Option<String>,
}

impl RouteRuntimeContext {
    fn from_destination(destination: &Destination) -> Self {
        Self {
            domain: destination.host.as_domain().map(str::to_string),
        }
    }

    fn input<'a>(
        &'a self,
        destination: &'a Destination,
        inbound_tag: Option<&'a str>,
    ) -> RouteInput<'a> {
        RouteInput::new(destination, inbound_tag, self.domain())
    }

    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    fn apply_sniffed_domain(&mut self, domain: Option<String>) {
        if let Some(domain) = domain {
            self.domain = Some(domain);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledRouteRule {
    rule_index: usize,
    matcher_summary: String,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    ip_cidr: Vec<IpNet>,
    ip_is_private: bool,
    ip_is_loopback: bool,
    ip_is_link_local: bool,
    port: Vec<u16>,
    inbound: Vec<String>,
    action: RouteAction,
}

impl CompiledRouteRule {
    fn compile(rule: RouteRule, rule_index: usize) -> Self {
        Self {
            rule_index,
            matcher_summary: build_matcher_summary(&rule),
            domain: rule
                .domain
                .into_iter()
                .map(|domain| normalize_domain_str(&domain))
                .collect(),
            domain_suffix: rule
                .domain_suffix
                .into_iter()
                .map(|suffix| normalize_domain_suffix(&suffix))
                .collect(),
            ip_cidr: rule.ip_cidr,
            ip_is_private: rule.ip_is_private,
            ip_is_loopback: rule.ip_is_loopback,
            ip_is_link_local: rule.ip_is_link_local,
            port: rule.port,
            inbound: rule.inbound,
            action: rule.action,
        }
    }

    fn action_kind(&self) -> &'static str {
        self.action.kind()
    }

    fn evaluate(
        &self,
        input: RouteInput<'_>,
        normalized_domain: Option<&str>,
    ) -> Result<(), RouteRuleMissReason> {
        self.matches_exact_domain(normalized_domain)?;
        self.matches_domain_suffix(normalized_domain)?;
        self.matches_ip_cidr(input.host())?;
        self.matches_ip_is_private(input.host())?;
        self.matches_ip_is_loopback(input.host())?;
        self.matches_ip_is_link_local(input.host())?;
        self.matches_port(input.destination.port)?;
        self.matches_inbound(input.inbound_tag)?;
        Ok(())
    }

    fn matches_exact_domain(
        &self,
        normalized_domain: Option<&str>,
    ) -> Result<(), RouteRuleMissReason> {
        if self.domain.is_empty() {
            return Ok(());
        }

        match normalized_domain {
            Some(domain) if self.domain.iter().any(|candidate| candidate == domain) => Ok(()),
            Some(_) => Err(RouteRuleMissReason::DomainMismatch),
            None => Err(RouteRuleMissReason::DomainAbsent),
        }
    }

    fn matches_domain_suffix(
        &self,
        normalized_domain: Option<&str>,
    ) -> Result<(), RouteRuleMissReason> {
        if self.domain_suffix.is_empty() {
            return Ok(());
        }

        match normalized_domain {
            Some(domain)
                if self
                    .domain_suffix
                    .iter()
                    .any(|suffix| matches_domain_suffix(domain, suffix)) =>
            {
                Ok(())
            }
            Some(_) => Err(RouteRuleMissReason::DomainSuffixMismatch),
            None => Err(RouteRuleMissReason::DomainAbsent),
        }
    }

    fn matches_ip_cidr(&self, host: &Host) -> Result<(), RouteRuleMissReason> {
        if self.ip_cidr.is_empty() {
            return Ok(());
        }

        match host {
            Host::Ip(ip) if self.ip_cidr.iter().any(|cidr| cidr.contains(ip)) => Ok(()),
            Host::Ip(_) => Err(RouteRuleMissReason::IpCidrMismatch),
            Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
        }
    }

    fn matches_ip_is_private(&self, host: &Host) -> Result<(), RouteRuleMissReason> {
        if !self.ip_is_private {
            return Ok(());
        }

        match host {
            Host::Ip(_) if is_private_or_unique_local(host) => Ok(()),
            Host::Ip(_) => Err(RouteRuleMissReason::IpNotPrivate),
            Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
        }
    }

    fn matches_ip_is_loopback(&self, host: &Host) -> Result<(), RouteRuleMissReason> {
        if !self.ip_is_loopback {
            return Ok(());
        }

        match host {
            Host::Ip(_) if is_loopback(host) => Ok(()),
            Host::Ip(_) => Err(RouteRuleMissReason::IpNotLoopback),
            Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
        }
    }

    fn matches_ip_is_link_local(&self, host: &Host) -> Result<(), RouteRuleMissReason> {
        if !self.ip_is_link_local {
            return Ok(());
        }

        match host {
            Host::Ip(_) if is_link_local(host) => Ok(()),
            Host::Ip(_) => Err(RouteRuleMissReason::IpNotLinkLocal),
            Host::Domain(_) => Err(RouteRuleMissReason::DestinationNotIp),
        }
    }

    fn matches_port(&self, port: u16) -> Result<(), RouteRuleMissReason> {
        if self.port.is_empty() || self.port.contains(&port) {
            Ok(())
        } else {
            Err(RouteRuleMissReason::PortMismatch)
        }
    }

    fn matches_inbound(&self, inbound_tag: Option<&str>) -> Result<(), RouteRuleMissReason> {
        if self.inbound.is_empty() {
            return Ok(());
        }

        match inbound_tag {
            Some(tag) if self.inbound.iter().any(|candidate| candidate == tag) => Ok(()),
            _ => Err(RouteRuleMissReason::InboundMismatch),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteRuleMissReason {
    DomainAbsent,
    DomainMismatch,
    DomainSuffixMismatch,
    DestinationNotIp,
    IpCidrMismatch,
    IpNotPrivate,
    IpNotLoopback,
    IpNotLinkLocal,
    PortMismatch,
    InboundMismatch,
}

impl RouteRuleMissReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::DomainAbsent => "domain_absent",
            Self::DomainMismatch => "domain_mismatch",
            Self::DomainSuffixMismatch => "domain_suffix_mismatch",
            Self::DestinationNotIp => "destination_not_ip",
            Self::IpCidrMismatch => "ip_cidr_mismatch",
            Self::IpNotPrivate => "ip_not_private",
            Self::IpNotLoopback => "ip_not_loopback",
            Self::IpNotLinkLocal => "ip_not_link_local",
            Self::PortMismatch => "port_mismatch",
            Self::InboundMismatch => "inbound_mismatch",
        }
    }
}

/// Static router that decides which outbound should handle a session.
///
/// The routing decision pipeline is a single ordered rule/action scan:
/// 1. Upgrade actions may enrich routing context and continue rule evaluation
/// 2. Final actions terminate routing with a decision
/// 3. If no rule produces a final action, the default final action is used
#[derive(Clone, Debug)]
pub struct Router {
    rules: Vec<CompiledRouteRule>,
    default_final_action: RouteFinalAction,
}

impl Router {
    pub fn new(default_final_action: RouteFinalAction) -> Self {
        Self {
            rules: Vec::new(),
            default_final_action,
        }
    }

    pub fn with_default_outbound(outbound_tag: impl Into<String>) -> Self {
        Self::new(RouteFinalAction::Route(RouteTarget::new(outbound_tag)))
    }

    pub fn default_final_action(&self) -> &RouteFinalAction {
        &self.default_final_action
    }

    pub fn with_rule(mut self, rule: RouteRule) -> Self {
        let rule_index = self.rules.len();
        self.rules
            .push(CompiledRouteRule::compile(rule, rule_index));
        self
    }

    pub fn with_rules<I>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = RouteRule>,
    {
        let start_index = self.rules.len();
        self.rules.extend(
            rules
                .into_iter()
                .enumerate()
                .map(|(offset, rule)| CompiledRouteRule::compile(rule, start_index + offset)),
        );
        self
    }

    pub fn select(&self, ctx: &SessionContext) -> RouteDecision {
        self.select_input(RouteInput::from_session(ctx))
    }

    pub fn select_input(&self, input: RouteInput<'_>) -> RouteDecision {
        let normalized_domain = input.domain.map(normalize_domain_str);

        for rule in &self.rules {
            if rule.evaluate(input, normalized_domain.as_deref()).is_err() {
                continue;
            }

            match &rule.action {
                RouteAction::Upgrade(_) => continue,
                RouteAction::Final(action) => {
                    return self.final_action_decision(action, RouteReason::Rule);
                }
            }
        }

        self.default_final_decision()
    }

    pub async fn route_stream(
        &self,
        input: StreamCarrier,
        ctx: SessionContext,
    ) -> Result<RouteResult<StreamCarrier>, RouteError> {
        let mut stream = input.stream;
        let inbound_tag = Some(ctx.meta.inbound_tag.as_str());
        let destination = &ctx.meta.destination;
        let mut route_context = RouteRuntimeContext::from_destination(destination);

        for rule in &self.rules {
            let route_input = route_context.input(destination, inbound_tag);
            let normalized_domain = route_input.domain.map(normalize_domain_str);
            log_route_rule_eval(&ctx, rule, route_input.domain);

            let evaluation = rule.evaluate(route_input, normalized_domain.as_deref());
            let Err(reason) = evaluation else {
                log_route_rule_match(&ctx, rule, route_input.domain);

                match &rule.action {
                    RouteAction::Upgrade(RouteUpgradeAction::Sniff(action)) => {
                        let domain_before = route_context.domain().map(str::to_string);
                        log_sniff_start(&ctx, action.timeout);
                        let sniff = sniff_stream_internal(stream, action.timeout).await;
                        log_sniff_result(&ctx, action.timeout, &sniff);
                        route_context.apply_sniffed_domain(sniff.outcome.domain.clone());
                        log_route_upgrade_applied(
                            &ctx,
                            rule,
                            domain_before.as_deref(),
                            route_context.domain(),
                        );
                        stream = Box::new(sniff.outcome.stream);
                    }
                    RouteAction::Final(action) => {
                        let decision = self.final_action_decision(action, RouteReason::Rule);
                        log_route_final_selected(
                            &ctx,
                            rule,
                            route_input.domain,
                            &decision.final_action,
                        );
                        return Ok(RouteResult {
                            ctx,
                            decision,
                            input: StreamCarrier::new(stream),
                        });
                    }
                }

                continue;
            };

            log_route_rule_miss(&ctx, rule, route_input.domain, reason);
        }

        let decision = self.default_final_decision();
        log_route_default_final_selected(&ctx, route_context.domain(), &decision.final_action);
        Ok(RouteResult {
            ctx,
            decision,
            input: StreamCarrier::new(stream),
        })
    }

    pub async fn route_packet(
        &self,
        input: PacketCarrier,
        ctx: SessionContext,
    ) -> Result<RouteResult<PacketCarrier>, RouteError> {
        let decision = self.select(&ctx);
        Ok(RouteResult {
            ctx,
            decision,
            input,
        })
    }

    fn final_action_decision(
        &self,
        action: &RouteFinalAction,
        reason: RouteReason,
    ) -> RouteDecision {
        RouteDecision {
            final_action: action.clone(),
            reason,
        }
    }

    fn default_final_decision(&self) -> RouteDecision {
        self.final_action_decision(&self.default_final_action, RouteReason::Final)
    }
}

impl RouteAction {
    fn kind(&self) -> &'static str {
        match self {
            Self::Upgrade(RouteUpgradeAction::Sniff(_)) => "sniff",
            Self::Final(action) => action.kind(),
        }
    }
}

impl RouteFinalAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Route(_) => "route",
            Self::HijackDns => "hijack-dns",
        }
    }
}

fn build_matcher_summary(rule: &RouteRule) -> String {
    let mut matchers = Vec::new();

    if !rule.domain.is_empty() {
        matchers.push("domain");
    }
    if !rule.domain_suffix.is_empty() {
        matchers.push("domain_suffix");
    }
    if !rule.ip_cidr.is_empty() {
        matchers.push("ip_cidr");
    }
    if rule.ip_is_private {
        matchers.push("ip_is_private");
    }
    if rule.ip_is_loopback {
        matchers.push("ip_is_loopback");
    }
    if rule.ip_is_link_local {
        matchers.push("ip_is_link_local");
    }
    if !rule.port.is_empty() {
        matchers.push("port");
    }
    if !rule.inbound.is_empty() {
        matchers.push("inbound");
    }

    if matchers.is_empty() {
        "none".to_string()
    } else {
        matchers.join(",")
    }
}

fn sanitize_optional_domain(domain: Option<&str>) -> String {
    domain
        .map(|value| sanitize_field(value).into_owned())
        .unwrap_or_else(|| "<none>".to_string())
}

fn log_route_rule_eval(
    ctx: &SessionContext,
    rule: &CompiledRouteRule,
    domain_before: Option<&str>,
) {
    let matcher_summary = sanitize_field(rule.matcher_summary.as_str()).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_rule_eval",
        session_id = ctx.meta.id,
        rule_index = rule.rule_index as u64,
        action_kind = rule.action_kind(),
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        "route rule evaluated"
    );
}

fn log_route_rule_match(
    ctx: &SessionContext,
    rule: &CompiledRouteRule,
    domain_before: Option<&str>,
) {
    let matcher_summary = sanitize_field(rule.matcher_summary.as_str()).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_rule_match",
        session_id = ctx.meta.id,
        rule_index = rule.rule_index as u64,
        action_kind = rule.action_kind(),
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        "route rule matched"
    );
}

fn log_route_rule_miss(
    ctx: &SessionContext,
    rule: &CompiledRouteRule,
    domain_before: Option<&str>,
    reason: RouteRuleMissReason,
) {
    let matcher_summary = sanitize_field(rule.matcher_summary.as_str()).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    debug!(
        event = "route_rule_miss",
        session_id = ctx.meta.id,
        rule_index = rule.rule_index as u64,
        action_kind = rule.action_kind(),
        matcher_summary = %matcher_summary,
        miss_reason = reason.as_str(),
        domain_before = %domain_before,
        "route rule missed"
    );
}

fn log_route_upgrade_applied(
    ctx: &SessionContext,
    rule: &CompiledRouteRule,
    domain_before: Option<&str>,
    domain_after: Option<&str>,
) {
    let matcher_summary = sanitize_field(rule.matcher_summary.as_str()).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    let domain_after = sanitize_optional_domain(domain_after);
    debug!(
        event = "route_upgrade_applied",
        session_id = ctx.meta.id,
        rule_index = rule.rule_index as u64,
        action_kind = rule.action_kind(),
        matcher_summary = %matcher_summary,
        domain_before = %domain_before,
        domain_after = %domain_after,
        "route upgrade applied"
    );
}

fn log_route_final_selected(
    ctx: &SessionContext,
    rule: &CompiledRouteRule,
    domain_before: Option<&str>,
    action: &RouteFinalAction,
) {
    let matcher_summary = sanitize_field(rule.matcher_summary.as_str()).into_owned();
    let domain_before = sanitize_optional_domain(domain_before);
    match action {
        RouteFinalAction::Route(target) => {
            let outbound = sanitize_field(&target.outbound_tag).into_owned();
            debug!(
                event = "route_final_selected",
                session_id = ctx.meta.id,
                rule_index = rule.rule_index as u64,
                action_kind = rule.action_kind(),
                matcher_summary = %matcher_summary,
                domain_before = %domain_before,
                outbound = %outbound,
                "route final action selected"
            );
        }
        RouteFinalAction::HijackDns => {
            debug!(
                event = "route_final_selected",
                session_id = ctx.meta.id,
                rule_index = rule.rule_index as u64,
                action_kind = rule.action_kind(),
                matcher_summary = %matcher_summary,
                domain_before = %domain_before,
                "route final action selected"
            );
        }
    }
}

fn log_route_default_final_selected(
    ctx: &SessionContext,
    domain_before: Option<&str>,
    action: &RouteFinalAction,
) {
    let domain_before = sanitize_optional_domain(domain_before);
    match action {
        RouteFinalAction::Route(target) => {
            let outbound = sanitize_field(&target.outbound_tag).into_owned();
            debug!(
                event = "route_default_final_selected",
                session_id = ctx.meta.id,
                action_kind = action.kind(),
                domain_before = %domain_before,
                outbound = %outbound,
                "route default final action selected"
            );
        }
        RouteFinalAction::HijackDns => {
            debug!(
                event = "route_default_final_selected",
                session_id = ctx.meta.id,
                action_kind = action.kind(),
                domain_before = %domain_before,
                "route default final action selected"
            );
        }
    }
}

fn log_sniff_start(ctx: &SessionContext, timeout: Duration) {
    let inbound_field = sanitize_field(ctx.meta.inbound_tag.as_str()).into_owned();
    info!(
        event = "sniff_start",
        session_id = ctx.meta.id,
        inbound_tag = %inbound_field,
        sniff_timeout_ms = timeout.as_millis() as u64,
        result = "start",
        "sniff started"
    );
}

fn log_sniff_result(
    ctx: &SessionContext,
    timeout: Duration,
    sniff: &SniffExecution<BoxedAsyncStream>,
) {
    let inbound_field = sanitize_field(ctx.meta.inbound_tag.as_str()).into_owned();
    let sniff_timeout_ms = timeout.as_millis() as u64;

    match &sniff.result {
        SniffResult::Matched { domain, protocol } => {
            let domain_field = sanitize_field(domain).into_owned();
            info!(
                event = "sniff_success",
                session_id = ctx.meta.id,
                inbound_tag = %inbound_field,
                sniff_timeout_ms,
                protocol = protocol.as_str(),
                domain = %domain_field,
                result = "matched",
                "sniff matched domain"
            );
        }
        SniffResult::Timeout => {
            info!(
                event = "sniff_timeout",
                session_id = ctx.meta.id,
                inbound_tag = %inbound_field,
                sniff_timeout_ms,
                result = "timeout",
                "sniff timed out"
            );
        }
        SniffResult::NotMatched => {
            info!(
                event = "sniff_no_match",
                session_id = ctx.meta.id,
                inbound_tag = %inbound_field,
                sniff_timeout_ms,
                result = "not_matched",
                "sniff did not match a supported domain"
            );
        }
        SniffResult::Unsupported => {
            if let Some(error) = &sniff.error {
                warn!(
                    event = "sniff_error",
                    session_id = ctx.meta.id,
                    inbound_tag = %inbound_field,
                    sniff_timeout_ms,
                    result = "error",
                    error = %error,
                    "sniff prefix read failed"
                );
            } else {
                info!(
                    event = "sniff_no_match",
                    session_id = ctx.meta.id,
                    inbound_tag = %inbound_field,
                    sniff_timeout_ms,
                    result = "unsupported",
                    "sniff prefix did not contain a supported protocol"
                );
            }
        }
    }
}

fn normalize_domain_str(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

fn normalize_domain_suffix(suffix: &str) -> String {
    suffix.trim().trim_start_matches('.').to_ascii_lowercase()
}

fn matches_domain_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

fn is_loopback(host: &Host) -> bool {
    match host {
        Host::Ip(ip) => ip.is_loopback(),
        Host::Domain(_) => false,
    }
}

fn is_private_or_unique_local(host: &Host) -> bool {
    match host {
        Host::Ip(std::net::IpAddr::V4(ip)) => ip.is_private(),
        Host::Ip(std::net::IpAddr::V6(ip)) => ip.is_unique_local(),
        Host::Domain(_) => false,
    }
}

fn is_link_local(host: &Host) -> bool {
    match host {
        Host::Ip(std::net::IpAddr::V4(ip)) => ip.is_link_local(),
        Host::Ip(std::net::IpAddr::V6(ip)) => ip.is_unicast_link_local(),
        Host::Domain(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    use crate::{Destination, Network, SessionContext, SessionMeta, StreamCarrier};
    use veex_test_tracing::{assert_has_event, captured_events, install_test_subscriber};

    use super::{RouteAction, RouteFinalAction, RouteInput, RouteReason, RouteRule, Router};

    fn build_ctx(destination: Destination) -> SessionContext {
        SessionContext::new(
            SessionMeta {
                id: 1,
                network: Network::Tcp,
                inbound_tag: "test".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        )
    }

    enum ReadStep {
        Data(Vec<u8>),
        Error(io::Error),
        Eof,
    }

    struct ScriptedStream {
        read_steps: VecDeque<ReadStep>,
    }

    impl ScriptedStream {
        fn new(read_steps: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                read_steps: read_steps.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read_steps.pop_front().unwrap_or(ReadStep::Eof) {
                ReadStep::Data(data) => {
                    buf.put_slice(&data);
                    Poll::Ready(Ok(()))
                }
                ReadStep::Error(err) => {
                    Poll::Ready(Err(io::Error::new(err.kind(), err.to_string())))
                }
                ReadStep::Eof => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for ScriptedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingStream;

    impl AsyncRead for PendingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn selects_default_final_for_normal_destinations() {
        let router = Router::with_default_outbound("proxy");
        let ctx = build_ctx(Destination::from_domain("example.com", 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Final);
    }

    #[test]
    fn private_destinations_do_not_bypass_without_explicit_rule() {
        let router = Router::with_default_outbound("proxy");
        let ctx = build_ctx(Destination::from_ip(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            53,
        ));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Final);
    }

    #[test]
    fn matches_domain_rule_exactly() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain: vec!["example.com".into()],
            ..RouteRule::new("proxy")
        });
        let ctx = build_ctx(Destination::from_domain("Example.COM", 443));

        let decision = router.select(&ctx);
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_domain_suffix_for_apex_and_subdomain() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            ..RouteRule::new("proxy")
        });

        let apex = Destination::from_domain("google.com", 443);
        let subdomain = Destination::from_domain("www.google.com", 443);

        let apex_decision =
            router.select_input(RouteInput::new(&apex, Some("test"), Some("google.com")));
        let subdomain_decision = router.select_input(RouteInput::new(
            &subdomain,
            Some("test"),
            Some("www.google.com"),
        ));

        assert_eq!(apex_decision.outbound_tag(), Some("proxy"));
        assert_eq!(apex_decision.reason, RouteReason::Rule);
        assert_eq!(subdomain_decision.outbound_tag(), Some("proxy"));
        assert_eq!(subdomain_decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_ip_cidr_rule_for_ip_destinations() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            ip_cidr: vec!["198.51.100.0/24".parse().unwrap()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("proxy"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn matches_private_loopback_and_link_local_rules_as_regular_rules() {
        let router = Router::with_default_outbound("proxy").with_rules([
            RouteRule {
                ip_is_loopback: true,
                ..RouteRule::new("loopback-direct")
            },
            RouteRule {
                ip_is_private: true,
                ..RouteRule::new("private-direct")
            },
            RouteRule {
                ip_is_link_local: true,
                ..RouteRule::new("link-local-direct")
            },
        ]);

        let loopback = Destination::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let private = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080);
        let link_local = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)), 8080);

        assert_eq!(
            router
                .select_input(RouteInput::new(&loopback, Some("test"), None))
                .outbound_tag(),
            Some("loopback-direct")
        );
        assert_eq!(
            router
                .select_input(RouteInput::new(&private, Some("test"), None))
                .outbound_tag(),
            Some("private-direct")
        );
        assert_eq!(
            router
                .select_input(RouteInput::new(&link_local, Some("test"), None))
                .outbound_tag(),
            Some("link-local-direct")
        );
    }

    #[test]
    fn matches_port_and_inbound_rules() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                port: vec![53],
                ..RouteRule::new("dns")
            },
            RouteRule {
                inbound: vec!["socks-in".into()],
                ..RouteRule::new("socks-out")
            },
        ]);
        let port_destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 53);
        let inbound_destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 80);

        let port_match = router.select_input(RouteInput::new(
            &port_destination,
            Some("redirect-in"),
            None,
        ));
        let inbound_match = router.select_input(RouteInput::new(
            &inbound_destination,
            Some("socks-in"),
            None,
        ));

        assert_eq!(port_match.outbound_tag(), Some("dns"));
        assert_eq!(port_match.reason, RouteReason::Rule);
        assert_eq!(inbound_match.outbound_tag(), Some("socks-out"));
        assert_eq!(inbound_match.reason, RouteReason::Rule);
    }

    #[test]
    fn requires_all_matchers_in_a_rule_to_match() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            port: vec![443],
            ..RouteRule::new("proxy")
        });
        let matching = Destination::from_domain("www.google.com", 443);
        let mismatched_port = Destination::from_domain("www.google.com", 80);

        let matching_decision = router.select_input(RouteInput::new(
            &matching,
            Some("test"),
            Some("www.google.com"),
        ));
        let mismatched_decision = router.select_input(RouteInput::new(
            &mismatched_port,
            Some("test"),
            Some("www.google.com"),
        ));

        assert_eq!(matching_decision.outbound_tag(), Some("proxy"));
        assert_eq!(matching_decision.reason, RouteReason::Rule);
        assert_eq!(mismatched_decision.outbound_tag(), Some("final"));
        assert_eq!(mismatched_decision.reason, RouteReason::Final);
    }

    #[test]
    fn final_rule_stops_pipeline_immediately() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                port: vec![443],
                ..RouteRule::new("first")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("second")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("first"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn can_return_hijack_dns_as_a_final_action() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            inbound: vec!["dns-in".into()],
            action: RouteAction::Final(RouteFinalAction::HijackDns),
            ..RouteRule::new("unused")
        });
        let destination = Destination::from_ip("127.0.0.1".parse().unwrap(), 53);

        let decision = router.select_input(RouteInput::new(&destination, Some("dns-in"), None));

        assert!(matches!(decision.final_action, RouteFinalAction::HijackDns));
        assert_eq!(decision.reason, RouteReason::Rule);
        assert_eq!(decision.outbound_tag(), None);
    }

    #[test]
    fn domain_rules_do_not_match_when_domain_is_absent() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                domain: vec!["example.com".into()],
                ..RouteRule::new("proxy")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("fallback-rule")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let decision = router.select_input(RouteInput::new(&destination, Some("test"), None));
        assert_eq!(decision.outbound_tag(), Some("fallback-rule"));
        assert_eq!(decision.reason, RouteReason::Rule);
    }

    #[test]
    fn can_be_rerun_after_domain_becomes_available() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            domain_suffix: vec!["google.com".into()],
            ..RouteRule::new("proxy")
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);

        let first = router.select_input(RouteInput::new(&destination, Some("test"), None));
        let second = router.select_input(RouteInput::new(
            &destination,
            Some("test"),
            Some("www.google.com"),
        ));

        assert_eq!(first.outbound_tag(), Some("final"));
        assert_eq!(first.reason, RouteReason::Final);
        assert_eq!(second.outbound_tag(), Some("proxy"));
        assert_eq!(second.reason, RouteReason::Rule);
    }

    #[tokio::test]
    async fn sniff_upgrade_injects_domain_and_replays_prefix() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(300))
            },
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 7,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );
        let payload = tls_client_hello_with_sni("www.google.com");

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(payload.clone()),
                    ReadStep::Eof,
                ]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");

        assert_eq!(routed.decision.outbound_tag(), Some("proxy"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);

        let mut replay = routed.input.stream;
        let mut replayed = Vec::new();
        replay
            .read_to_end(&mut replayed)
            .await
            .expect("prefixed stream should replay sniffed bytes");
        assert_eq!(replayed, payload);
    }

    #[tokio::test]
    async fn sniff_upgrade_does_not_rerun_earlier_final_rules() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(300))
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 8,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(tls_client_hello_with_sni("www.google.com")),
                    ReadStep::Eof,
                ]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");

        assert_eq!(routed.decision.outbound_tag(), Some("late"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);
    }

    #[tokio::test]
    async fn private_route_rule_can_share_pipeline_with_sniff_and_domain_rules() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(300))
            },
            RouteRule {
                ip_is_private: true,
                ..RouteRule::new("direct")
            },
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
        ]);
        let destination = Destination::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 11,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(tls_client_hello_with_sni("www.google.com")),
                    ReadStep::Eof,
                ]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");

        assert_eq!(routed.decision.outbound_tag(), Some("direct"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);
    }

    #[tokio::test]
    async fn default_final_action_runs_when_no_rule_produces_a_final_decision() {
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            inbound: vec!["tproxy-in".into()],
            ..RouteRule::sniff(Duration::from_millis(10))
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 12,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(StreamCarrier::new(Box::new(PendingStream)), ctx)
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("final"));
        assert_eq!(routed.decision.reason, RouteReason::Final);
    }

    #[tokio::test]
    async fn sniff_timeout_falls_through_to_later_rules() {
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(10))
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 9,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(StreamCarrier::new(Box::new(PendingStream)), ctx)
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("late"));
        assert_eq!(routed.decision.reason, RouteReason::Rule);
    }

    #[tokio::test]
    async fn sniff_read_error_is_traced_without_failing_route() {
        let (_guard, events) = install_test_subscriber();
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                inbound: vec!["tproxy-in".into()],
                ..RouteRule::sniff(Duration::from_millis(300))
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 10,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([ReadStep::Error(
                    io::Error::other("boom"),
                )]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("late"));

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "sniff_error",
            &[
                ("session_id", "10"),
                ("inbound_tag", "tproxy-in"),
                ("result", "error"),
                ("level", "WARN"),
            ],
        );
    }

    #[tokio::test]
    async fn route_explainability_traces_rule_miss_and_final_selection() {
        let (_guard, events) = install_test_subscriber();
        let router = Router::with_default_outbound("final").with_rules([
            RouteRule {
                domain_suffix: vec!["google.com".into()],
                ..RouteRule::new("proxy")
            },
            RouteRule {
                port: vec![443],
                ..RouteRule::new("late")
            },
        ]);
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 13,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(StreamCarrier::new(Box::new(PendingStream)), ctx)
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("late"));

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "route_rule_eval",
            &[
                ("session_id", "13"),
                ("rule_index", "0"),
                ("action_kind", "route"),
                ("matcher_summary", "domain_suffix"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_rule_miss",
            &[
                ("session_id", "13"),
                ("rule_index", "0"),
                ("miss_reason", "domain_absent"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_rule_match",
            &[
                ("session_id", "13"),
                ("rule_index", "1"),
                ("action_kind", "route"),
                ("matcher_summary", "port"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_final_selected",
            &[
                ("session_id", "13"),
                ("rule_index", "1"),
                ("action_kind", "route"),
                ("outbound", "late"),
                ("level", "DEBUG"),
            ],
        );
    }

    #[tokio::test]
    async fn route_explainability_traces_sniff_upgrade_and_default_final() {
        let (_guard, events) = install_test_subscriber();
        let router = Router::with_default_outbound("final").with_rule(RouteRule {
            inbound: vec!["tproxy-in".into()],
            ..RouteRule::sniff(Duration::from_millis(300))
        });
        let destination = Destination::from_ip("198.51.100.10".parse().unwrap(), 443);
        let ctx = SessionContext::new(
            SessionMeta {
                id: 14,
                network: Network::Tcp,
                inbound_tag: "tproxy-in".into(),
                peer: SocketAddr::from(([127, 0, 0, 1], 40000)),
                destination,
                start: Instant::now(),
            },
            Vec::new(),
        );

        let routed = router
            .route_stream(
                StreamCarrier::new(Box::new(ScriptedStream::new([
                    ReadStep::Data(tls_client_hello_with_sni("www.google.com")),
                    ReadStep::Eof,
                ]))),
                ctx,
            )
            .await
            .expect("stream routing should succeed");
        assert_eq!(routed.decision.outbound_tag(), Some("final"));
        assert_eq!(routed.decision.reason, RouteReason::Final);

        let events = captured_events(&events);
        assert_has_event(
            &events,
            "route_rule_match",
            &[
                ("session_id", "14"),
                ("rule_index", "0"),
                ("action_kind", "sniff"),
                ("matcher_summary", "inbound"),
                ("domain_before", "<none>"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_upgrade_applied",
            &[
                ("session_id", "14"),
                ("rule_index", "0"),
                ("action_kind", "sniff"),
                ("domain_before", "<none>"),
                ("domain_after", "www.google.com"),
                ("level", "DEBUG"),
            ],
        );
        assert_has_event(
            &events,
            "route_default_final_selected",
            &[
                ("session_id", "14"),
                ("action_kind", "route"),
                ("domain_before", "www.google.com"),
                ("outbound", "final"),
                ("level", "DEBUG"),
            ],
        );
    }

    fn tls_client_hello_with_sni(server_name: &str) -> Vec<u8> {
        let server_name_bytes = server_name.as_bytes();

        let mut server_name_ext = Vec::new();
        let list_len = 1 + 2 + server_name_bytes.len();
        server_name_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        server_name_ext.push(0);
        server_name_ext.extend_from_slice(&(server_name_bytes.len() as u16).to_be_bytes());
        server_name_ext.extend_from_slice(server_name_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name_ext);

        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&[0x03, 0x03]);
        client_hello.extend_from_slice(&[0u8; 32]);
        client_hello.push(0);
        client_hello.extend_from_slice(&2u16.to_be_bytes());
        client_hello.extend_from_slice(&[0x13, 0x01]);
        client_hello.push(1);
        client_hello.push(0);
        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hello_len = client_hello.len() as u32;
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&client_hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
