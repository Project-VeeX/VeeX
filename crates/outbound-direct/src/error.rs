use std::io;

use veex_core::{ProxyError, Result};

pub(crate) fn validate_routing_mark_support(routing_mark: Option<u32>) -> Result<()> {
    if routing_mark.is_some() && !cfg!(target_os = "linux") {
        return Err(ProxyError::Config(
            "direct outbound routing_mark is only supported on linux".into(),
        ));
    }

    Ok(())
}

pub(crate) fn io_error_with_context(context: impl Into<String>, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), format!("{}: {source}", context.into()))
}

pub(crate) fn last_os_error_with_context(context: impl Into<String>) -> io::Error {
    let source = io::Error::last_os_error();
    io::Error::new(source.kind(), format!("{}: {source}", context.into()))
}
