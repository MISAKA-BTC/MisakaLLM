//! MIL-Fin — finance / investment-analysis profile (design §18.3).
//!
//! The value proposition: deeper investment analysis than centralized models
//! typically give, (a) grounded on FSL-verifiable facts and (b) fully private
//! (positions/strategy invisible to the provider, §15.1). The profile enforces
//! an output form where every factual claim carries an FSL `fact_id` the client
//! can re-check — the hallucination control for an 8B model (§18.3).

use crate::AgentProfile;

const SYSTEM_PROMPT: &str = "\
You are MIL-Fin, a financial and investment-analysis assistant running on the \
MISAKA Inference Lane. You operate as neutral infrastructure: the operator of \
this system prompt sets policy, not a hidden vendor layer.\n\n\
Grounding and citations:\n\
- Ground factual claims in the market snapshot and fact corpus provided in \
context. Every factual assertion (a price, an on-chain metric, an earnings \
figure) MUST cite its source with an inline `[fact:<fact_id>]` tag so the \
client can verify it against the Fact Settlement Layer (FSL). Do not state a \
verifiable fact without a `fact:` citation.\n\
- State the as-of time of any market snapshot you rely on, and reflect data \
freshness in your answer.\n\n\
Output discipline:\n\
- Present analysis as explicit scenarios with probability estimates and \
quantified risk (expected loss ranges), not a single point prediction.\n\
- Do NOT use absolute or guarantee language ('will definitely', 'guaranteed', \
'必ず', '確実に', 'no risk'). Express uncertainty honestly.\n\
- This is general, non-personalized information of the same kind found in books \
and the financial press — it is NOT individualized investment advice, custody, \
or order execution.\n\n\
Scope: you generate analysis only. You do not hold assets and do not place \
orders; any execution is the user's own client-side, user-signed action.";

/// A default RAG manifest identifier for the FSL fact corpus (§18.3). In a
/// deployment this is the on-chain-pinned manifest hash of the corpus snapshot.
const RAG_MANIFEST: &str = "misaka-mil-v1/rag/fsl-market-facts";

/// MIL-Fin exposes no client-executed tools in v1 (analysis only, §18.3);
/// v2 order placement is a separate, user-signed client tool.
const TOOL_SCHEMA: &str = "[]";

pub fn profile() -> AgentProfile {
    AgentProfile {
        name: "MIL-Fin".to_string(),
        system_prompt: SYSTEM_PROMPT.to_string(),
        tool_schema: TOOL_SCHEMA.to_string(),
        rag_index_manifest: RAG_MANIFEST.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discipline;

    #[test]
    fn system_prompt_enforces_citations_and_bans_absolutes() {
        let p = profile();
        assert!(p.system_prompt.contains("fact:"));
        assert!(p.system_prompt.to_lowercase().contains("scenario"));
        assert!(p.system_prompt.contains("必ず") || p.system_prompt.contains("確実に"));
    }

    #[test]
    fn citation_and_discipline_helpers_apply_to_fin_output() {
        // a well-formed answer cites facts and avoids absolutes
        let good = "Asset X trades at 100 [fact:px-x-2026-07-05]; base case +5% (p=0.4), downside -15% (p=0.2).";
        let ids = discipline::extract_fact_ids(good);
        assert_eq!(ids, vec!["px-x-2026-07-05"]);
        assert!(discipline::flag_absolute_language(good).is_empty());
        // an FSL cross-check passes when all cited ids are known
        assert!(discipline::citations_verified(good, &["px-x-2026-07-05".to_string()]));

        // a non-compliant answer is flagged
        let bad = "X will definitely double, 確実に profit.";
        assert!(!discipline::flag_absolute_language(bad).is_empty());
        assert!(discipline::extract_fact_ids(bad).is_empty());
    }
}
