use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, ServerInfo},
    schemars, tool, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::Deserialize;
use std::process::Command;

#[derive(Clone, Default)]
pub struct U7sTools {
    #[expect(
        dead_code,
        reason = "read by #[tool_router] macro-generated ServerHandler impl"
    )]
    tool_router: ToolRouter<U7sTools>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiagnosticsParams {
    /// Optional path to Cargo.toml manifest (defaults to workspace root)
    #[serde(default)]
    pub manifest: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BdShowParams {
    /// Bead ID (e.g. "mayor-4z5")
    pub id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EmptyParams {}

/// Parse the JSON lines output of `cargo check --message-format=json` into a
/// flat list of primary diagnostic spans.  Filters out `note` and `help`
/// severities; only keeps messages with `reason == "compiler-message"`.
pub fn parse_diagnostics(stdout: &str) -> Vec<serde_json::Value> {
    let mut diagnostics = Vec::new();
    for line in stdout.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg["reason"] != "compiler-message" {
            continue;
        }
        let m = &msg["message"];
        let severity = m["level"].as_str().unwrap_or("unknown");
        if severity == "note" || severity == "help" {
            continue;
        }
        if let Some(spans) = m["spans"].as_array() {
            for span in spans.iter().filter(|s| s["is_primary"] == true) {
                diagnostics.push(serde_json::json!({
                    "file": span["file_name"],
                    "line": span["line_start"],
                    "col": span["column_start"],
                    "severity": severity,
                    "message": m["message"],
                }));
            }
        }
    }
    diagnostics
}

#[tool_router]
impl U7sTools {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Run cargo check --workspace and return structured diagnostics as a JSON array.
    #[tool(
        description = "Run cargo check --workspace and return structured diagnostics. Each item: {file, line, col, severity, message}."
    )]
    async fn get_diagnostics(
        &self,
        Parameters(p): Parameters<DiagnosticsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut cmd = Command::new("cargo");
        cmd.args(["check", "--workspace", "--message-format=json"]);
        if let Some(manifest) = &p.manifest {
            cmd.args(["--manifest-path", manifest]);
        }

        let output = cmd.output().map_err(|e| {
            McpError::internal_error(format!("failed to run cargo check: {e}"), None)
        })?;

        let diagnostics = parse_diagnostics(&String::from_utf8_lossy(&output.stdout));
        let json = serde_json::to_string_pretty(&diagnostics).unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    /// List all open beads that are ready to work (no blockers).
    #[tool(description = "List beads ready to work (no blockers, open status). Returns JSON.")]
    async fn bd_ready(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        let output = Command::new("bd")
            .args(["list", "--status=open", "--json"])
            .output()
            .map_err(|e| McpError::internal_error(format!("failed to run bd: {e}"), None))?;

        let text = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Show full details of a bead issue by ID.
    #[tool(
        description = "Show full details of a bead by ID (e.g. 'mayor-4z5'). Returns JSON with title, description, priority, status, notes."
    )]
    async fn bd_show(
        &self,
        Parameters(p): Parameters<BdShowParams>,
    ) -> Result<CallToolResult, McpError> {
        let output = Command::new("bd")
            .args(["show", &p.id, "--json"])
            .output()
            .map_err(|e| McpError::internal_error(format!("failed to run bd: {e}"), None))?;

        let text = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            String::from_utf8_lossy(&output.stderr).to_string()
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

impl ServerHandler for U7sTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

/// Start the MCP server, serving over stdio until the client disconnects.
pub async fn run() -> Result<()> {
    let service = U7sTools::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_diagnostics ────────────────────────────────────────────────────

    /// Empty input produces an empty list — avoids panics on clean builds.
    #[test]
    fn parse_diagnostics_empty_input() {
        let result = parse_diagnostics("");
        assert!(result.is_empty());
    }

    /// Lines that are not valid JSON are silently skipped.
    #[test]
    fn parse_diagnostics_ignores_non_json_lines() {
        let result = parse_diagnostics("not json at all\nanother bad line");
        assert!(result.is_empty());
    }

    /// JSON lines with a reason other than "compiler-message" are ignored.
    #[test]
    fn parse_diagnostics_ignores_non_compiler_message_reason() {
        let line = r#"{"reason":"build-script-executed","package_id":"foo"}"#;
        let result = parse_diagnostics(line);
        assert!(result.is_empty());
    }

    /// `note` severity messages must be filtered out — they are too noisy.
    #[test]
    fn parse_diagnostics_filters_note_severity() {
        let line = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "level": "note",
                "message": "some note",
                "spans": [{
                    "is_primary": true,
                    "file_name": "src/lib.rs",
                    "line_start": 1,
                    "column_start": 1
                }]
            }
        })
        .to_string();
        let result = parse_diagnostics(&line);
        assert!(result.is_empty(), "note-level messages must be filtered");
    }

    /// `help` severity messages must be filtered out.
    #[test]
    fn parse_diagnostics_filters_help_severity() {
        let line = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "level": "help",
                "message": "try this instead",
                "spans": [{
                    "is_primary": true,
                    "file_name": "src/lib.rs",
                    "line_start": 5,
                    "column_start": 3
                }]
            }
        })
        .to_string();
        let result = parse_diagnostics(&line);
        assert!(result.is_empty(), "help-level messages must be filtered");
    }

    /// Only primary spans are included — secondary spans carry context that
    /// is not actionable on its own and would clutter the output.
    #[test]
    fn parse_diagnostics_includes_only_primary_spans() {
        let line = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "level": "error",
                "message": "type mismatch",
                "spans": [
                    {
                        "is_primary": false,
                        "file_name": "src/other.rs",
                        "line_start": 10,
                        "column_start": 5
                    },
                    {
                        "is_primary": true,
                        "file_name": "src/lib.rs",
                        "line_start": 42,
                        "column_start": 7
                    }
                ]
            }
        })
        .to_string();
        let result = parse_diagnostics(&line);
        assert_eq!(result.len(), 1, "only the primary span should appear");
        assert_eq!(result[0]["file"], "src/lib.rs");
        assert_eq!(result[0]["line"], 42);
        assert_eq!(result[0]["col"], 7);
        assert_eq!(result[0]["severity"], "error");
        assert_eq!(result[0]["message"], "type mismatch");
    }

    /// Warnings are included because they represent actionable compiler feedback.
    #[test]
    fn parse_diagnostics_includes_warnings() {
        let line = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "level": "warning",
                "message": "unused variable",
                "spans": [{
                    "is_primary": true,
                    "file_name": "src/main.rs",
                    "line_start": 3,
                    "column_start": 9
                }]
            }
        })
        .to_string();
        let result = parse_diagnostics(&line);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["severity"], "warning");
    }

    /// Multiple messages across multiple lines are all collected.
    #[test]
    fn parse_diagnostics_collects_multiple_messages() {
        fn make_error(file: &str, line: u32, msg: &str) -> String {
            serde_json::json!({
                "reason": "compiler-message",
                "message": {
                    "level": "error",
                    "message": msg,
                    "spans": [{
                        "is_primary": true,
                        "file_name": file,
                        "line_start": line,
                        "column_start": 1
                    }]
                }
            })
            .to_string()
        }

        let input = format!(
            "{}\n{}",
            make_error("src/a.rs", 1, "err A"),
            make_error("src/b.rs", 2, "err B")
        );
        let result = parse_diagnostics(&input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["file"], "src/a.rs");
        assert_eq!(result[1]["file"], "src/b.rs");
    }

    /// A message with no spans produces no diagnostics — there is nothing to
    /// point at, so we don't emit a placeholder entry.
    #[test]
    fn parse_diagnostics_message_without_spans_produces_no_entries() {
        let line = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "level": "error",
                "message": "aborting due to previous error",
                "spans": []
            }
        })
        .to_string();
        let result = parse_diagnostics(&line);
        assert!(result.is_empty());
    }

    /// A compiler-message with missing `level` field falls back to "unknown"
    /// and is still included (not filtered as note/help).
    #[test]
    fn parse_diagnostics_missing_level_falls_back_to_unknown() {
        let line = serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "message": "something weird",
                "spans": [{
                    "is_primary": true,
                    "file_name": "src/x.rs",
                    "line_start": 99,
                    "column_start": 1
                }]
            }
        })
        .to_string();
        let result = parse_diagnostics(&line);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["severity"], "unknown");
    }

    // ── param struct deserialization ─────────────────────────────────────────

    /// DiagnosticsParams.manifest defaults to None when omitted — this is what
    /// allows callers to omit the field without getting a deserialization error.
    #[test]
    fn diagnostics_params_manifest_defaults_to_none() {
        let p: DiagnosticsParams = serde_json::from_str("{}").unwrap();
        assert!(p.manifest.is_none());
    }

    /// DiagnosticsParams.manifest is set when provided.
    #[test]
    fn diagnostics_params_manifest_is_set_when_provided() {
        let p: DiagnosticsParams =
            serde_json::from_str(r#"{"manifest": "path/to/Cargo.toml"}"#).unwrap();
        assert_eq!(p.manifest.as_deref(), Some("path/to/Cargo.toml"));
    }

    /// BdShowParams requires the `id` field.
    #[test]
    fn bd_show_params_requires_id() {
        let p: BdShowParams = serde_json::from_str(r#"{"id": "mayor-4z5"}"#).unwrap();
        assert_eq!(p.id, "mayor-4z5");
    }

    /// EmptyParams deserializes from an empty object without error.
    #[test]
    fn empty_params_deserializes() {
        let _p: EmptyParams = serde_json::from_str("{}").unwrap();
    }
}
