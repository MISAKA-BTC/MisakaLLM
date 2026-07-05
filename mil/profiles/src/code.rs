//! MIL-Code — development-assistance profile (design §18.4).
//!
//! The differentiator: code never gets absorbed into training (§15.1) and the
//! model that produced an answer is provenance-fixed (§17.3) — decisive for
//! orgs that forbid sending source to a third party. Tools are executed
//! **client-side**: the model only emits function calls; the requester's
//! machine runs `file_read` / `grep` / `run_tests` / `git`, so no repo content
//! leaves the client except the context the user approved (and that travels
//! E2EE). Provider builds no sandbox (§18.4).

use crate::AgentProfile;

const SYSTEM_PROMPT: &str = "\
You are MIL-Code, a software-development assistant running on the MISAKA \
Inference Lane. You operate as neutral infrastructure; the operator of this \
system prompt sets policy.\n\n\
Tools run on the USER'S machine, not yours. When you need to inspect or change \
the workspace, emit a function call to one of the exposed tools (file_read, \
grep, run_tests, git). You never execute anything yourself and you never see \
the repository except the context the user has explicitly shared with you.\n\n\
Context discipline:\n\
- Assume a bounded context window. Ask for the specific files or symbols you \
need via `file_read`/`grep` rather than requesting the whole repository.\n\
- Keep local search and summarization on the client side; do not ask the model \
to hold more than it needs.\n\n\
Scope: chat and agentic assistance (v1). Editor inline (FIM) completion is out \
of scope for this profile.";

const RAG_MANIFEST: &str = "";

/// OpenAI-format `tools` array (§18.4). All executed client-side.
const TOOL_SCHEMA: &str = r#"[
  {
    "type": "function",
    "function": {
      "name": "file_read",
      "description": "Read a file from the user's workspace (client-side).",
      "parameters": {
        "type": "object",
        "properties": {
          "path": {"type": "string", "description": "Workspace-relative file path"},
          "start_line": {"type": "integer"},
          "end_line": {"type": "integer"}
        },
        "required": ["path"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "grep",
      "description": "Search the user's workspace for a pattern (client-side).",
      "parameters": {
        "type": "object",
        "properties": {
          "pattern": {"type": "string"},
          "path": {"type": "string", "description": "Directory or file to search"}
        },
        "required": ["pattern"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "run_tests",
      "description": "Run the project's tests (client-side) and return the result.",
      "parameters": {
        "type": "object",
        "properties": {
          "target": {"type": "string", "description": "Optional test target or filter"}
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "git",
      "description": "Run a read-only git command in the user's workspace (client-side).",
      "parameters": {
        "type": "object",
        "properties": {
          "args": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["args"]
      }
    }
  }
]"#;

pub fn profile() -> AgentProfile {
    AgentProfile {
        name: "MIL-Code".to_string(),
        system_prompt: SYSTEM_PROMPT.to_string(),
        tool_schema: TOOL_SCHEMA.to_string(),
        rag_index_manifest: RAG_MANIFEST.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_schema_is_valid_json_with_four_client_tools() {
        let p = profile();
        let tools = p.tools();
        let arr = tools.as_array().expect("tools is a JSON array");
        assert_eq!(arr.len(), 4);
        for t in arr {
            assert_eq!(t["type"], "function");
            assert!(t["function"]["name"].is_string());
        }
        assert!(p.system_prompt.contains("client-side") || p.system_prompt.contains("USER'S machine"));
    }
}
