use thiserror::Error;

use crate::session::SessionContext;

use super::RouteDecision;

pub struct RouteResult<I> {
    pub ctx: SessionContext,
    pub decision: RouteDecision,
    pub input: I,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Proxy(#[from] crate::ProxyError),
}

impl From<RouteError> for crate::ProxyError {
    fn from(err: RouteError) -> Self {
        match err {
            RouteError::Proxy(err) => err,
        }
    }
}
