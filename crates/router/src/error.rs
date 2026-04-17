use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Proxy(#[from] veex_core::ProxyError),
}

impl From<RouteError> for veex_core::ProxyError {
    fn from(err: RouteError) -> Self {
        match err {
            RouteError::Proxy(err) => err,
        }
    }
}
