//! Command registry and built-in example commands.
//!
//! Commands are registered by name and invoked with JSON input/output.

use crate::context::AppContext;
use crate::types::*;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Instant;

/// Signature for all engine commands.
pub type CommandHandler = fn(Value, &AppContext) -> Result<Value, CommandError>;

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("{0}")]
    Other(String),
}

impl CommandError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            CommandError::InvalidInput(_) => ErrorCode::InvalidInput,
            CommandError::Io(_) => ErrorCode::IoError,
            CommandError::PermissionDenied(_) => ErrorCode::PermissionDenied,
            CommandError::Other(_) => ErrorCode::InternalError,
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct CommandRegistry {
    handlers: HashMap<String, CommandHandler>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        let mut reg = Self {
            handlers: HashMap::new(),
        };
        // Register built-in commands
        reg.register("ping", cmd_ping);
        reg.register("read_file", cmd_read_file);
        reg.register("write_file", cmd_write_file);
        reg
    }

    pub fn register(&mut self, name: &str, handler: CommandHandler) {
        self.handlers.insert(name.to_string(), handler);
    }

    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.handlers.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Execute a command by name and return a full CommandResult.
    pub fn execute(&self, name: &str, args: Value, ctx: &AppContext) -> CommandResult {
        let run_id = new_run_id();
        let start = Instant::now();

        let handler = match self.handlers.get(name) {
            Some(h) => h,
            None => {
                return result_err(
                    "call",
                    name,
                    &run_id,
                    start.elapsed().as_millis() as u64,
                    ErrorCode::InvalidInput,
                    format!("unknown command: {}", name),
                );
            }
        };

        match handler(args, ctx) {
            Ok(data) => {
                let mut r = result_ok("call", name, &run_id, start.elapsed().as_millis() as u64);
                r.data = Some(data);
                r
            }
            Err(e) => result_err(
                "call",
                name,
                &run_id,
                start.elapsed().as_millis() as u64,
                e.error_code(),
                e.to_string(),
            ),
        }
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Built-in commands
// ===========================================================================

/// `ping` – returns { "pong": true }. Proves wiring works.
fn cmd_ping(_args: Value, _ctx: &AppContext) -> Result<Value, CommandError> {
    Ok(serde_json::json!({ "pong": true }))
}

/// `read_file` – read a file, return its contents as a UTF-8 string.
///
/// Args: `{ "path": "/absolute/path" }`
/// Returns: `{ "content": "...", "size_bytes": 123 }`
fn cmd_read_file(args: Value, ctx: &AppContext) -> Result<Value, CommandError> {
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::InvalidInput("missing 'path' string field".into()))?;

    let path = std::path::Path::new(path_str);
    let data = ctx.fs().read_file(path).map_err(|e| match e {
        crate::traits::CapError::PermissionDenied(m) => CommandError::PermissionDenied(m),
        crate::traits::CapError::Io(io) => CommandError::Io(io),
        other => CommandError::Other(other.to_string()),
    })?;

    let content = String::from_utf8_lossy(&data);
    Ok(serde_json::json!({
        "content": content,
        "size_bytes": data.len(),
    }))
}

/// `write_file` – write string content to a file.
///
/// Args: `{ "path": "/absolute/path", "content": "hello" }`
/// Returns: `{ "bytes_written": 5 }`
fn cmd_write_file(args: Value, ctx: &AppContext) -> Result<Value, CommandError> {
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::InvalidInput("missing 'path' string field".into()))?;
    let content = args
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::InvalidInput("missing 'content' string field".into()))?;

    let path = std::path::Path::new(path_str);
    let data = content.as_bytes();
    ctx.fs().write_file(path, data).map_err(|e| match e {
        crate::traits::CapError::PermissionDenied(m) => CommandError::PermissionDenied(m),
        crate::traits::CapError::Io(io) => CommandError::Io(io),
        other => CommandError::Other(other.to_string()),
    })?;

    Ok(serde_json::json!({ "bytes_written": data.len() }))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AppContext;

    #[test]
    fn test_ping_command() {
        let ctx = AppContext::default_headless();
        let reg = CommandRegistry::new();
        let result = reg.execute("ping", serde_json::json!({}), &ctx);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.data.unwrap()["pong"], true);
    }

    #[test]
    fn test_unknown_command() {
        let ctx = AppContext::default_headless();
        let reg = CommandRegistry::new();
        let result = reg.execute("nonexistent", serde_json::json!({}), &ctx);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.error.unwrap().code, ErrorCode::InvalidInput);
    }

    #[test]
    fn test_read_write_file() {
        let ctx = AppContext::default_headless();
        let reg = CommandRegistry::new();

        let tmp = std::env::temp_dir().join("engine_test_rw.txt");
        let path_str = tmp.to_str().unwrap();

        // Write
        let w = reg.execute(
            "write_file",
            serde_json::json!({ "path": path_str, "content": "hello engine" }),
            &ctx,
        );
        assert_eq!(w.status, Status::Pass);

        // Read back
        let r = reg.execute("read_file", serde_json::json!({ "path": path_str }), &ctx);
        assert_eq!(r.status, Status::Pass);
        assert_eq!(r.data.unwrap()["content"], "hello engine");

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_list_commands() {
        let reg = CommandRegistry::new();
        let names = reg.list();
        assert!(names.contains(&"ping"));
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
    }
}
