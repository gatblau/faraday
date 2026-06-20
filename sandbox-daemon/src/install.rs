//! ADR-031 install helper: merge the daemon's MCP front-door entry into an MCP client
//! config (e.g. Claude Code's `~/.claude.json`) **without clobbering** existing servers.
//! Kept in the binary (not a shell script) so the logic is version-locked, testable, and
//! reused by every platform installer (macOS now, Windows in a later phase).

use serde_json::{json, Map, Value};

/// Merge `{ "mcpServers": { <server_name>: { "command": <binary>, "args": ["mcp-stdio"] } } }`
/// into `existing` (or a fresh object when `None`/empty), preserving every other key and
/// server. **Idempotent** — re-running updates our entry in place, never duplicates.
///
/// Returns the pretty-printed merged JSON, or an `Err` (and writes nothing) when
/// `existing` is present but is not a JSON object, or `mcpServers` exists but is not an
/// object — so a malformed user config is never destroyed.
pub fn merge_mcp_config(
    existing: Option<&str>,
    server_name: &str,
    binary_path: &str,
) -> Result<String, String> {
    let mut root: Value = match existing {
        Some(s) if !s.trim().is_empty() => serde_json::from_str(s)
            .map_err(|e| format!("existing config is not valid JSON: {e}"))?,
        _ => Value::Object(Map::new()),
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "existing config is not a JSON object".to_string())?;
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| "mcpServers is present but is not an object".to_string())?;
    servers.insert(
        server_name.to_string(),
        json!({ "command": binary_path, "args": ["mcp-stdio"] }),
    );
    serde_json::to_string_pretty(&root).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::merge_mcp_config;
    use serde_json::Value;

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn creates_entry_from_absent_config() {
        let out = merge_mcp_config(None, "faradayd", "/usr/local/bin/faradayd").unwrap();
        let v = parse(&out);
        assert_eq!(
            v["mcpServers"]["faradayd"]["command"],
            "/usr/local/bin/faradayd"
        );
        assert_eq!(v["mcpServers"]["faradayd"]["args"][0], "mcp-stdio");
    }

    #[test]
    fn preserves_other_servers_and_keys() {
        let existing = r#"{"otherKey": 1, "mcpServers": {"other": {"command": "x"}}}"#;
        let out = merge_mcp_config(Some(existing), "faradayd", "/bin/p").unwrap();
        let v = parse(&out);
        assert_eq!(v["otherKey"], 1, "unrelated top-level key preserved");
        assert_eq!(
            v["mcpServers"]["other"]["command"], "x",
            "other server preserved"
        );
        assert_eq!(
            v["mcpServers"]["faradayd"]["command"], "/bin/p",
            "ours added"
        );
    }

    #[test]
    fn is_idempotent() {
        let once = merge_mcp_config(None, "faradayd", "/bin/p").unwrap();
        let twice = merge_mcp_config(Some(&once), "faradayd", "/bin/p").unwrap();
        let v = parse(&twice);
        assert_eq!(
            v["mcpServers"].as_object().unwrap().len(),
            1,
            "no duplicate entry on re-run"
        );
    }

    #[test]
    fn refuses_malformed_json() {
        assert!(merge_mcp_config(Some("{not json"), "faradayd", "/bin/p").is_err());
    }

    #[test]
    fn refuses_non_object_mcpservers() {
        let existing = r#"{"mcpServers": "oops"}"#;
        assert!(merge_mcp_config(Some(existing), "faradayd", "/bin/p").is_err());
    }
}
