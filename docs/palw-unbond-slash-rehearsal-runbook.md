# PALW provider unbond / slash rehearsal + custody/incident runbook

The provider unbond, DA challenge/response/timeout, and slash mechanisms are tooling- and
consensus-complete, but the operator lifecycle was never captured as a **scripted, self-checking
rehearsal** with monitoring, rollback, incident, and key-custody procedures. This runbook and
`scripts/palw-unbond-slash-rehearsal.sh` close that operational gap. It is the rehearsal procedure;
executing it on a live multi-node network (and the accompanying withholding/retention soak) remains an
activation requirement.

## Scope

- **Rehearsed here:** Active bond → owner-signed unbond request → release delay → collateral sweep;
  and DA-challenge withholding → post-deadline timeout evidence → `Slashed` → proof the slashed
  collateral cannot be swept.
- **Not covered:** standing up the network; multi-node adversarial withholding/reorg soak; long DA
  retention soak. Those remain launch requirements.

## Safety model

- **Dry-run by default.** Every mutating step runs the CLI's own `--dry-run`, which builds, owner-signs,
  validates, and runs live registry/funding preflights **without** submitting. The whole rehearsal can be
  walked on a live network with zero on-chain effect. `--live` submits for real.
- **Irreversibility (know before `--live`):** an unbond *request* begins the exit and cannot be undone;
  a *sweep* is a final spend; a *slash* is an objective burn/forfeit — the collateral is neither
  returned nor transferred. Rehearse in dry-run first; only go `--live` on a throwaway rehearsal bond.
- **The un-sweepable invariant is asserted, not assumed.** The rehearsal attempts to sweep the slashed
  bond and treats **success as a failure**. Consensus independently pins this: a valid post-deadline
  `PalwDaTimeoutEvidenceV1` stages `PalwProviderBondMutation::Slash`, and `ProviderBondSpendFilter`
  keeps output 0 permanently unspendable (`consensus/src/pipeline/virtual_processor/utxo_validation.rs`
  and its tests). `Slashed` also denies reward and exit.

## Prerequisites

- A reachable node wRPC (borsh) endpoint running `--utxoindex` (and, for the slash phase, PALW active).
- The provider-bond **owner** ML-DSA-87 seed, held **off the node** (see Key custody). It both signs the
  request/timeout/response and funds the carrier transactions (the node enforces funder == owner).
- A rehearsal provider bond outpoint (`txid:index`). For `--live`, use a disposable bond you are willing
  to lose to the slash phase.

## Run it

```sh
# Full dry-run walk (no on-chain effect):
scripts/palw-unbond-slash-rehearsal.sh \
  --node-wrpc-borsh 127.0.0.1:27210 --network testnet-110 --network-id PALW_NETWORK_DOMAIN_U32 \
  --owner-key /secure/provider-owner.seed \
  --provider-bond REHEARSAL_BOND_TXID:INDEX \
  --challenge-id EXPIRED_CHALLENGE_HEX128 \
  --phase all

# Live (only on a disposable rehearsal bond): add --live
```

`--phase unbond` and `--phase slash` run one lifecycle at a time.

## Phase A — unbond

1. `palw-status --provider-bond ...` — expect `effective_status: active`.
2. `palw-provider-unbond request` (dry-run) — builds the owner-signed `PalwProviderUnbondRequestV1`,
   funds from mature UTXOs (never the bond), and runs live preflights.
3. **Monitor:** after a live request, `palw-status` reports `unbonding` and a `release_daa_score`.
   The bond stays slashable for the whole unbonding window; equivocation/timeout before release still
   slashes it.
4. Wait until the node's sink DAA score reaches `release_daa_score`.
5. `palw-provider-unbond sweep` (dry-run) — refused before the release DAA; succeeds after, spending the
   collateral back to the owner script.

## Phase B — slash (withholding path)

1. `palw-status` — baseline.
2. **Withhold:** do not answer the target challenge; let its response deadline lapse. (Contrast: the
   `palw-da-auto-respond` tool is what an honest provider runs to *avoid* this.)
3. `palw-payload da-timeout --challenge-id ... --provider-bond ... --out timeout.borsh` — build the
   post-deadline `0x3c` evidence (stateless-validated on write).
4. `--live`: `palw-submit --kind da-timeout --payload-file timeout.borsh` — submit it.
5. **Verify:** `palw-status` reports `slashed`.
6. **Prove un-sweepable:** `palw-provider-unbond sweep --dry-run` on the slashed bond — MUST be refused.
   The script fails the rehearsal if it is not.

## Monitoring signals

- `palw-status` per bond: `effective_status` (active/unbonding/slashed), `release_daa_score`,
  `slashed_at_daa_score`, `unbond_request_daa_score`.
- Open challenges on a bond: `getPalwState` now returns `da_challenges` (challenge id, sampled chunk,
  response-deadline DAA). Run `palw-da-auto-respond` (plan-only) as a monitor to see due responses.
- Node logs: `admitted and archived Object-v2 …` (DA admission), timeout/slash application, and the
  auto-responder's per-cycle `skip`/`due`/`answered` lines.
- Alert when: a challenge's remaining window drops below the responder's `--safety-margin-daa`; any bond
  becomes `unbonding`/`slashed` unexpectedly; the auto-responder cycle errors.

## Rollback

- Dry-run steps change nothing — the safe default for validating configuration and connectivity.
- There is **no rollback** for a live unbond request, sweep, or slash. The mitigation is procedural:
  rehearse in dry-run, gate `--live` behind a disposable bond, and require a second operator to confirm
  any live exit.

## Incident response

- **Open challenge discovered:** ensure `palw-da-auto-respond --enable-auto-response` is running and
  serving the object bytes; if the owner key is unavailable, use the manual `da-inspect`/`da-response` +
  `palw-submit` path from `palw-da-object-v2-operations.md` before the deadline.
- **Unexpected `unbonding`:** an unbond request was submitted — verify it was authorized; the bond stays
  slashable through the window; do not sweep until the cause is understood.
- **Unexpected `slashed`:** collateral is forfeit and permanently unspendable. Never attempt to sweep it
  (it will be refused). Capture the timeout evidence and challenge for the incident record.
- **Responder down:** challenges accrue toward their deadlines; restore the responder or answer manually
  before the earliest `response_deadline_daa_score`.

## Key custody

- The provider **owner** key stays **off** the node (ADR-0011 key separation; the node holds no owner
  keys and cannot sign 0x3b/unbond). Store the seed with `0600` on an operator-controlled host; supply it
  to the CLI via `--owner-key`/`KASPA_PQ_VALIDATOR_KEY` only for the duration of a signing run.
- The same owner key signs the 0x3b response, the unbond request, and funds carriers. Treat its host as
  the trust boundary for both availability and exit. Rotation requires re-registering the provider bond
  with a new owner; there is no in-place owner-key change for an existing bond.
- For `--live` rehearsals, use a dedicated seed and a disposable bond so the slash phase never risks a
  production bond.

## Status

- Rehearsal driver, this runbook, and the monitoring/rollback/incident/custody procedures: **done.**
- Remaining: execute the rehearsal `--live` on a multi-node testnet, then the multi-node adversarial
  withholding/retention soak. No preset enables PALW acceptance; this rehearsal does not change that.
