use std::{io, path::Path};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitCodeHint {
    Config = 2,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid config file path `{path}`: {message}")]
    FilePath { path: String, message: String },
    #[error("failed to read config file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("json parse error at {path}: {message}")]
    Json { path: String, message: String },
    #[error("config validation error at {path}: {message}")]
    Validation { path: String, message: String },
    #[error("config semantic error at {path}: {message}")]
    Semantic { path: String, message: String },
}

impl ConfigError {
    pub fn file_path(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::FilePath {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn io_path(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: display_path(path),
            source,
        }
    }

    pub fn json(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Json {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn validation(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn semantic(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Semantic {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn exit_code_hint(&self) -> ExitCodeHint {
        ExitCodeHint::Config
    }
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
