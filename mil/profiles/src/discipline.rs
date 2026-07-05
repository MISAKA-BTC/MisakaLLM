//! Client-side output discipline for MIL-Fin (design §18.3).
//!
//! These are the checks a client (SDK / app footer) applies to model output:
//! extract the `[fact:<id>]` citations so they can be cross-checked against the
//! FSL, and flag absolute/guarantee language the profile forbids. They run on
//! the requester side (the trust terminus, §15.4), not in the model.

/// Extract the `<id>` of every `[fact:<id>]` citation in output order.
pub fn extract_fact_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let bytes = text.as_bytes();
    let needle = b"[fact:";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let start = i + needle.len();
            if let Some(rel_end) = text[start..].find(']') {
                let id = text[start..start + rel_end].trim();
                if !id.is_empty() {
                    ids.push(id.to_string());
                }
                i = start + rel_end + 1;
                continue;
            }
        }
        i += 1;
    }
    ids
}

/// Every cited fact_id must be in the known (FSL-verified) set — the structural
/// "facts are checkable" property (§18.3). An answer with no citations trivially
/// passes (it asserts no verifiable facts); the caller decides whether a
/// citation was required.
pub fn citations_verified(text: &str, known_ids: &[String]) -> bool {
    extract_fact_ids(text).iter().all(|id| known_ids.contains(id))
}

/// Absolute / guarantee phrases MIL-Fin must not emit (§18.3). Case-insensitive
/// for the ASCII entries; the Japanese entries match as-is.
const ABSOLUTE_PHRASES: &[&str] = &["guaranteed", "will definitely", "no risk", "risk-free", "certain to", "必ず", "確実に", "絶対に"];

/// Return the forbidden phrases present in `text` (empty ⇒ compliant). A client
/// footer can surface these or block the turn.
pub fn flag_absolute_language(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    ABSOLUTE_PHRASES
        .iter()
        .copied()
        .filter(|p| if p.is_ascii() { lower.contains(&p.to_lowercase()) } else { text.contains(*p) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_multiple_fact_ids() {
        let t = "A is 10 [fact:a-1] and B is 20 [fact:b-2]; C unknown.";
        assert_eq!(extract_fact_ids(t), vec!["a-1", "b-2"]);
        // malformed / empty citations are skipped without panic
        assert!(extract_fact_ids("[fact:] [fact:x").is_empty());
    }

    #[test]
    fn citation_verification_against_fsl_set() {
        let t = "x [fact:a-1] y [fact:b-2]";
        assert!(citations_verified(t, &["a-1".into(), "b-2".into(), "c-3".into()]));
        assert!(!citations_verified(t, &["a-1".into()])); // b-2 not known
        assert!(citations_verified("no facts here", &[])); // no citations → passes
    }

    #[test]
    fn flags_absolute_language_ascii_and_japanese() {
        assert!(flag_absolute_language("this is GUARANTEED to work").contains(&"guaranteed"));
        assert!(flag_absolute_language("必ず儲かる").contains(&"必ず"));
        assert!(flag_absolute_language("a balanced, probabilistic view").is_empty());
    }
}
