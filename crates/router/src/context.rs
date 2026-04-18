use veex_core::{
    io::{PacketCarrier, StreamCarrier},
    session::SessionContext,
    types::{Destination, Host},
};

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

    pub(crate) fn host(self) -> &'a Host {
        &self.destination.host
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteRuntimeContext {
    domain: Option<String>,
}

impl RouteRuntimeContext {
    pub(crate) fn from_destination(destination: &Destination) -> Self {
        Self {
            domain: destination.host.as_domain().map(str::to_string),
        }
    }

    pub(crate) fn input<'a>(
        &'a self,
        destination: &'a Destination,
        inbound_tag: Option<&'a str>,
    ) -> RouteInput<'a> {
        RouteInput::new(destination, inbound_tag, self.domain())
    }

    pub(crate) fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub(crate) fn apply_sniffed_domain(&mut self, domain: Option<String>) {
        if let Some(domain) = domain {
            self.domain = Some(domain);
        }
    }
}

pub(crate) enum PipelineRequest {
    Stream(StreamCarrier),
    Packet(PacketCarrier),
}
