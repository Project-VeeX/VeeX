use crate::{
    error::RouteError,
    result::RouteResult,
    rule::{CompiledRouteRule, RouteFinalAction, RouteRule, RouteTarget},
    runtime,
};
use veex_core::{
    io::{PacketCarrier, StreamCarrier},
    session::SessionContext,
};

#[derive(Clone, Debug)]
pub struct Router {
    pub(crate) rules: Vec<CompiledRouteRule>,
    pub(crate) default_final_action: RouteFinalAction,
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

    pub async fn route_stream(
        &self,
        input: StreamCarrier,
        ctx: SessionContext,
    ) -> Result<RouteResult<StreamCarrier>, RouteError> {
        runtime::route_stream(self, input, ctx).await
    }

    pub async fn route_packet(
        &self,
        input: PacketCarrier,
        ctx: SessionContext,
    ) -> Result<RouteResult<PacketCarrier>, RouteError> {
        runtime::route_packet(self, input, ctx).await
    }
}
