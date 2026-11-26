//! File deliverables need descriptor-relative filesystem operations.

use ua_core::{UaError, UaResult};

use crate::registry::ToolCtx;

fn unsupported() -> UaError {
    UaError::denied("file_deliverables_unsupported", "file deliverables require a Unix hub")
}

pub fn source(_: &ToolCtx, _: &str, _: &str) -> UaResult<Vec<u8>> {
    Err(unsupported())
}

pub struct Destination {
    pub identity: String,
}

impl Destination {
    pub fn configured(_: &ToolCtx) -> UaResult<Self> {
        Err(unsupported())
    }

    pub fn check_absent(&self, _: &str) -> UaResult<()> {
        Err(unsupported())
    }

    pub fn matches(&self, _: &str, _: &str) -> UaResult<bool> {
        Err(unsupported())
    }

    pub fn check_unpublished(&self, _: &str, _: &str) -> UaResult<()> {
        Err(unsupported())
    }

    pub fn confirm_published(&self, _: &str, _: &str, _: &str) -> UaResult<bool> {
        Err(unsupported())
    }

    pub fn publish(&self, _: &str, _: &str, _: &[u8], _: &str) -> UaResult<()> {
        Err(unsupported())
    }

    pub fn clean_staging(&self, _: &str) {}
}
