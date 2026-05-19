use anyhow::Result;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerInfo},
    schemars,
    tool, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::process::Command;

#[derive(Clone)]
struct U7sTools {
    #[allow(dead_code)]
    tool_router: ToolRouter<U7sTools>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DiagnosticsParams {
    /// Optional path to Cargo.toml manifest (defaults to workspace root)
    #[serde(default)]
    manifest: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BdShowParams {
    /// Bead ID (e.g. "mayor-4z5")
    id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmptyParams {}

#[tool_router]
impl U7sTools {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Run cargo check --workspace and return structured diagnostics as a JSON array.
    #[tool(description = "Run cargo check --workspace and return structured diagnostics. Each item: {file, line, col, severity, message}.")]
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

        let mut diagnostics = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
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

        let json = serde_json::to_string_pretty(&diagnostics).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
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
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Show full details of a bead issue by ID.
    #[tool(description = "Show full details of a bead by ID (e.g. 'mayor-4z5'). Returns JSON with title, description, priority, status, notes.")]
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
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

impl ServerHandler for U7sTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let service = U7sTools::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
