use std::{net::SocketAddr, time::Duration};

use tracing::{info, warn};
use veex_core::{
    ProxyError,
    dns::{DnsRequest, DnsResponse, ResolveContext},
    logging::sanitize_field,
};

use crate::{
    cache::DnsCacheValue,
    types::{DnsSelection, DnsServer},
    wire::DnsQueryInfo,
};

use super::{DnsExecutor, runtime::DnsServerRuntime};

pub(super) struct QueryFinishContext<'a> {
    pub request: &'a DnsRequest,
    pub query: &'a DnsQueryInfo,
    pub server: &'a DnsServer,
    pub selection: &'a DnsSelection,
    pub query_id: u64,
    pub cache_hit: bool,
    pub winner_server_tag: &'a str,
}

impl DnsExecutor {
    pub(super) fn log_cache_lookup(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_lookup",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache lookup started"
        );
    }

    pub(super) fn log_cache_hit(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        value: &DnsCacheValue,
    ) {
        info!(
            event = "dns_cache_hit",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            winner_server = %sanitize_field(&value.stored_server_tag),
            ttl_secs = value.ttl.as_secs(),
            "dns cache hit"
        );
    }

    pub(super) fn log_cache_miss(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_miss",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache miss"
        );
    }

    pub(super) fn log_cache_expired(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_expired",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache entry expired"
        );
    }

    pub(super) fn log_cache_bypass(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
    ) {
        info!(
            event = "dns_cache_bypass",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            route_reason = %selection.reason.as_str(),
            selection_scope = %sanitize_field(&selection.candidate_server_tags.join(",")),
            "dns cache bypassed for this query"
        );
    }

    pub(super) fn log_cache_store(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection_scope: &str,
        winner_server_tag: &str,
        ttl: Duration,
    ) {
        info!(
            event = "dns_cache_store",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selection_scope = %sanitize_field(selection_scope),
            winner_server = %sanitize_field(winner_server_tag),
            ttl_secs = ttl.as_secs(),
            "dns cache entry stored"
        );
    }

    pub(super) fn log_upstream_query_start(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
    ) {
        info!(
            event = "dns_upstream_query_start",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            detour = %sanitize_field(server.server.detour_tag()),
            transport = %server.server.transport.as_str(),
            route_reason = %selection.reason.as_str(),
            candidate_count = selection.candidate_server_tags.len() as u64,
            "dns upstream query started"
        );
    }

    pub(super) fn log_upstream_query_won(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
        concurrent: bool,
    ) {
        info!(
            event = "dns_upstream_query_won",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            route_reason = %selection.reason.as_str(),
            concurrent,
            "dns upstream query produced the winning response"
        );
    }

    pub(super) fn log_upstream_query_cancelled(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
    ) {
        info!(
            event = "dns_upstream_query_cancelled",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            route_reason = %selection.reason.as_str(),
            "dns upstream query cancelled after another winner was selected"
        );
    }

    pub(super) fn log_upstream_query_failed(
        &self,
        query_id: u64,
        query_kind: &str,
        query_name: &str,
        query_type: u16,
        selection: &DnsSelection,
        server: &DnsServerRuntime,
        err: &ProxyError,
    ) {
        warn!(
            event = "dns_upstream_query_failed",
            query_id,
            query_kind = %query_kind,
            query_name = %sanitize_field(query_name),
            query_type = query_type as u64,
            selected_server = %sanitize_field(&selection.server_tag),
            server = %sanitize_field(&server.server.tag),
            route_reason = %selection.reason.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream query failed"
        );
    }

    pub(super) fn log_query_start(
        &self,
        request: &DnsRequest,
        query: &DnsQueryInfo,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
    ) {
        info!(
            event = "dns_query_start",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(&query.name),
            query_type = query.qtype as u64,
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            candidate_count = selection.candidate_server_tags.len() as u64,
            transport = %server.transport.as_str(),
            "dns query started"
        );
    }

    pub(super) fn on_client_response(&self, _query_name: &str, _response: &DnsResponse) {
        // Reserved for a future reverse_mapping side effect. This remains a no-op
        // until the DNS subsystem grows an explicit reverse map store.
    }

    pub(super) fn log_query_finish(&self, context: QueryFinishContext<'_>, response: &DnsResponse) {
        info!(
            event = "dns_query_finish",
            query_id = context.query_id,
            inbound = %sanitize_field(&context.request.inbound_tag),
            ingress_protocol = %context.request.protocol.as_str(),
            query_name = %sanitize_field(&context.query.name),
            query_type = context.query.qtype as u64,
            server = %sanitize_field(&context.server.tag),
            winner_server = %sanitize_field(context.winner_server_tag),
            detour = %sanitize_field(context.server.detour_tag()),
            destination = %sanitize_field(&context.server.destination.to_string()),
            route_reason = %context.selection.reason.as_str(),
            transport = %context.server.transport.as_str(),
            cache_hit = context.cache_hit,
            response_bytes = response.raw_message.len() as u64,
            "dns query finished"
        );
        info!(
            event = "dns_query_success",
            query_id = context.query_id,
            inbound = %sanitize_field(&context.request.inbound_tag),
            ingress_protocol = %context.request.protocol.as_str(),
            query_name = %sanitize_field(&context.query.name),
            query_type = context.query.qtype as u64,
            server = %sanitize_field(&context.server.tag),
            winner_server = %sanitize_field(context.winner_server_tag),
            detour = %sanitize_field(context.server.detour_tag()),
            destination = %sanitize_field(&context.server.destination.to_string()),
            route_reason = %context.selection.reason.as_str(),
            transport = %context.server.transport.as_str(),
            cache_hit = context.cache_hit,
            response_bytes = response.raw_message.len() as u64,
            "dns query succeeded"
        );
    }

    pub(super) fn log_query_failure(
        &self,
        request: &DnsRequest,
        query: &DnsQueryInfo,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        err: &ProxyError,
    ) {
        warn!(
            event = "dns_query_failed",
            query_id,
            inbound = %sanitize_field(&request.inbound_tag),
            ingress_protocol = %request.protocol.as_str(),
            query_name = %sanitize_field(&query.name),
            query_type = query.qtype as u64,
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            destination = %sanitize_field(&server.destination.to_string()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dns upstream receive failed"
        );
    }

    pub(super) fn log_domain_resolve_start(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
    ) {
        info!(
            event = "domain_resolve_start",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            "dial-side domain resolution started"
        );
    }

    pub(super) fn log_domain_resolve_success(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
        addresses: &[SocketAddr],
    ) {
        let addresses_field = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        info!(
            event = "domain_resolve_success",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            resolved_addrs = %sanitize_field(&addresses_field),
            "dial-side domain resolution succeeded"
        );
    }

    pub(super) fn log_domain_resolve_failure(
        &self,
        domain: &str,
        port: u16,
        server: &DnsServer,
        selection: &DnsSelection,
        query_id: u64,
        context: &ResolveContext,
        err: &ProxyError,
    ) {
        warn!(
            event = "domain_resolve_failed",
            query_id,
            domain = %sanitize_field(domain),
            port,
            purpose = %context.purpose.as_str(),
            recursion_depth = context.recursion_depth as u64,
            caller_outbound = %sanitize_field(context.caller_outbound_tag.as_deref().unwrap_or("")),
            caller_dns_server = %sanitize_field(context.caller_dns_server_tag.as_deref().unwrap_or("")),
            explicit_server = %sanitize_field(context.explicit_server_tag.as_deref().unwrap_or("")),
            server = %sanitize_field(&server.tag),
            detour = %sanitize_field(server.detour_tag()),
            route_reason = %selection.reason.as_str(),
            transport = %server.transport.as_str(),
            error_kind = ?err.kind(),
            error = %err,
            "dial-side domain resolution failed"
        );
    }
}
