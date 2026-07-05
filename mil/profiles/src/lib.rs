//! MIL Agent Profiles (design §18.2).
//!
//! A profile differentiates a vertical WITHOUT forking the canonical model
//! (§18.2): it is a public bundle of `{ system_prompt, tool_schema,
//! rag_index_manifest }` composed **client-side** into the prompt, so the
//! provider stays unchanged and GPU-neutral. Its [`crate::AgentProfile::profile_id`]
//! is the on-chain-registered identity (`misaka_mil_core::model::profile_id`).
//!
//! Two v1 profiles ship here:
//! - [`mil_fin`] (§18.3): finance/investment analysis over FSL-cited facts,
//!   with output discipline (scenarios + probabilities + loss ranges, no
//!   absolute claims).
//! - [`mil_code`] (§18.4): dev assistance with **client-side** tool execution
//!   (file read / grep / test / git) — the model only emits function calls; the
//!   requester's machine runs them.
//!
//! Composition is deterministic and pure: [`AgentProfile::compose`] turns a
//! user prompt into the OpenAI `messages` array bytes that the requester seals
//! into the MIL channel (the provider's [`HttpBackend`](misaka_mil_provider)
//! accepts exactly this). No network, no model calls here.

pub mod code;
pub mod discipline;
pub mod fin;

use kaspa_hashes::Hash64;
use misaka_mil_core::model::profile_id;
use serde_json::{Value, json};

/// A composable agent profile (§18.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfile {
    /// Human-readable label (e.g. "MIL-Fin").
    pub name: String,
    /// The public system prompt (policy layer — §18.1 system-prompt sovereignty).
    pub system_prompt: String,
    /// Tool schema as a canonical JSON string (OpenAI `tools` array). Empty
    /// (`"[]"`) if the profile exposes no tools.
    pub tool_schema: String,
    /// RAG index manifest identifier / hash string (the fact corpus the client
    /// injects; §18.3 FSL). Empty if none.
    pub rag_index_manifest: String,
}

impl AgentProfile {
    /// The on-chain profile identity `Hash64_k("misaka-mil-v1/profile" ‖
    /// len‖system_prompt ‖ len‖tool_schema ‖ len‖rag_index_manifest)` — the
    /// SAME derivation `MilGovernance`/`ModelRegistry` would anchor.
    pub fn profile_id(&self) -> Hash64 {
        profile_id(self.system_prompt.as_bytes(), self.tool_schema.as_bytes(), self.rag_index_manifest.as_bytes())
    }

    /// The parsed tool schema (OpenAI `tools` array).
    pub fn tools(&self) -> Value {
        serde_json::from_str(&self.tool_schema).unwrap_or_else(|_| json!([]))
    }

    /// Compose the profile + a user prompt into an OpenAI `messages` array.
    /// This is what the requester seals as the MIL prompt frame; the provider
    /// backend forwards it verbatim (§18.2 — client-side composition).
    pub fn compose_messages(&self, user_prompt: &str) -> Value {
        json!([
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ])
    }

    /// The composed messages as UTF-8 JSON bytes — the exact `prompt` a
    /// `RequesterClient::run_prompt` sends.
    pub fn compose_prompt_bytes(&self, user_prompt: &str) -> Vec<u8> {
        serde_json::to_vec(&self.compose_messages(user_prompt)).expect("in-memory JSON serialization is infallible")
    }
}

/// The MIL-Fin profile (§18.3).
pub fn mil_fin() -> AgentProfile {
    fin::profile()
}

/// The MIL-Code profile (§18.4).
pub fn mil_code() -> AgentProfile {
    code::profile()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ids_are_distinct_and_deterministic() {
        let fin = mil_fin();
        let code = mil_code();
        assert_eq!(fin.profile_id(), mil_fin().profile_id());
        assert_ne!(fin.profile_id(), code.profile_id());
    }

    #[test]
    fn compose_produces_valid_openai_messages() {
        let p = mil_fin();
        let bytes = p.compose_prompt_bytes("What is the risk profile of asset X?");
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v[0]["role"], "system");
        assert_eq!(v[1]["role"], "user");
        assert!(v[0]["content"].as_str().unwrap().contains("fact_id"));
    }

    #[test]
    fn code_profile_exposes_client_side_tools() {
        let p = mil_code();
        let tools = p.tools();
        let names: Vec<String> =
            tools.as_array().unwrap().iter().map(|t| t["function"]["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"file_read".to_string()));
        assert!(names.contains(&"run_tests".to_string()));
    }
}
