//! Code family: symbol indexing and repository maps (`fs_*_symbols`,
//! `fs_repo_map`), `read_image`, `format_render`, `detect_dev_servers`,
//! `python_lint_and_format` and the offline docset tools (`dash_*`).
//!
//! Paths go through the workspace family's sandbox: indexing, symbol listing
//! and images stay inside the workspace root; `detect_dev_servers` may also
//! read an absolute path inside a read root.

mod dash;
mod devservers;
mod format;
#[cfg(feature = "code-intel")]
mod index;
#[cfg(feature = "code-intel")]
pub mod lang;
pub mod lint;
pub mod media;

use ua_store::SchemaPart;

use crate::registry::Registry;

pub use devservers::scan_dir as scan_dev_servers;
pub use format::format_render;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "code.v1",
    sql: "
CREATE TABLE IF NOT EXISTS code_symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace TEXT NOT NULL,
    file_path TEXT NOT NULL,
    language TEXT NOT NULL,
    symbol_name TEXT NOT NULL,
    symbol_type TEXT NOT NULL,
    symbol_kind TEXT NOT NULL,
    parent_name TEXT,
    signature TEXT NOT NULL DEFAULT '',
    docstring TEXT NOT NULL DEFAULT '',
    line_no INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_code_symbols_file ON code_symbols(workspace, file_path, line_no);
CREATE INDEX IF NOT EXISTS idx_code_symbols_name ON code_symbols(workspace, symbol_name);
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA]
}

pub fn register(r: &mut Registry) {
    dash::register(r);
    devservers::register(r);
    format::register(r);
    #[cfg(feature = "code-intel")]
    index::register(r);
    lint::register(r);
    media::register(r);
}
