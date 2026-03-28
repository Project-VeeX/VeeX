//! Redirect inbound implementation placeholder for Task 06.

use veex_core::Result;

pub const SO_ORIGINAL_DST: i32 = 80;
pub const IP6T_SO_ORIGINAL_DST: i32 = 80;

#[derive(Clone, Debug)]
pub struct RedirectInbound {
    tag: String,
}

impl RedirectInbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}


