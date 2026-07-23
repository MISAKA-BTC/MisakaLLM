# ADR: PALW public/value activation readiness — definition of done and honest gate ledger

Status: **In progress.** This ADR defines exactly what "the stage where public/value activation is
possible" means, tracks every gate, and draws the honest line between gates that can be closed by
writing code and gates that cannot. It is the definition-of-done for the goal
"finish permissionless snapshot auth, automatic 0x3b submission, the Windows/CUDA 72h soak, and the
unbond/slash rehearsal to the stage where public/value activation is possible."

## What "activation possible" means

Activation is a **separate, explicitly reviewed** change that sets `palw_algo4_accept = true` for a
**fresh Header-v4 re-genesis identity** (new suffix, ports, seeds, empty datadir). No shipped preset
enables it, and nothing in this program flips it. "Activation possible" is the state in which that flip
is *defensible*: every code gate is complete and reviewed, and every operational gate has been run on
real hardware and a real network. This ADR does not authorize the flip; it makes the remaining distance
explicit and honest. Fabricating any gate (soak evidence, review sign-off, hardware runs) would defeat
the purpose and cause real financial harm, since PALW carries bonds/slashing/escrow.

## Gate ledger

### A. Code gates (can be closed by implementation + tests + review)

| Gate | Status | Evidence / remaining |
|---|---|---|
| Automatic 0x3b response (discovery + deadline-aware submission) | **Code complete** | getPalwState `da_challenges` + `palw-da-auto-respond` (node `35c4d6c`); engine 5/5 + wire roundtrip. Live withholding soak is an operational gate (§B). |
| Permissionless snapshot auth — pure verifier | **Complete** | `verify_support_rows_against_transported_headers`, `reconstruct_selected_parent_state_from_pruning_payload`, and the composed `verify_chain_derived_pruning_boundary` (node `2b8139c`, `82d2330`); 17/17. |
| Permissionless snapshot auth — activation lever | **Complete** | `Config::palw_permissionless_snapshot_auth` (default false); no preset sets it. |
| Permissionless snapshot auth — provenance + fenced admission (1b) | **Remaining** | Add `ChainDerivedHeaderBundle` provenance + auth-bundle carrier; admit `(v4, that)` only when the lever is on; reject until 1c is wired. |
| Permissionless snapshot auth — importer wiring (1c) | **Remaining** | In `prepare_pruning_point_palw_snapshot_import`, derive `paid_work_nullifiers` / `da_state_root` / `legacy_overlay_root` from the transported boundary and call the verifier **before** stage/`db.write`. Test: rejection precedes any durable write. |
| Permissionless snapshot auth — P2P transport + PoW auth (1d) | **Remaining** | Transport the descendant Header-v4 header(s) + support-row header preimages (bounded); PoW/target-validate the descendant header and authenticate the transported DNS `OverlaySnapshot` — the trust root replacing the operator pin. |
| G6 anti-spam header-flood bound | **StopShip design** | Valid-sibling traffic causes O(reindexed-subtree) reachability row rewrites (`reindex_intervals`/`propagate_interval`). Needs a **reviewed** bounded-reachability/allocation redesign or a consensus-validity sibling bound, then re-measurement. Not to be rushed. |

### B. Operational gates (cannot be closed by writing code — irreducibly external)

These do not have a code representation that I can complete. They are listed so "activation possible" is
honest, not so they can be checked off from a keyboard.

| Gate | Why it is external | Readiness |
|---|---|---|
| 72h Windows/CUDA endurance soak | Needs the physical RTX host powered on + 72h of real wall-clock. | Harness/launcher/runbook ready (qwen `4121131`); **host offline** (last seen ~1d). Starts when powered on. |
| Live multi-node pruning/catch-up/reorg + DA-withholding soak | Needs a real multi-node network running over time. | Rehearsal driver + runbook ready (node `fdaeac5`); execute `--live` on a testnet. |
| Independent security review | Needs a human reviewer other than the author, especially for the permissionless-auth ordering and the G6 redesign. | Pending; ADRs written to make review tractable. |
| Re-genesis ceremony | An operational decision to allocate a new network identity/seeds/datadir and flip acceptance after review. | Not started; §5 of `palw-public-value-header-v4-antispam.md` is the procedure. |

## The honest boundary

I can drive the **A** gates to completion and I will (1b → 1c → 1d, then the G6 design for review). The
**B** gates are not code and cannot be satisfied by an agent writing and testing code; they require real
hardware time, a real network, human review, and an operational launch decision. I will not fabricate
any of them, and I will not flip `palw_algo4_accept`. When the A gates are complete and reviewed and the
B gates have genuinely been run, activation is *possible* — a separate change may then flip acceptance on
a fresh re-genesis candidate. Until then this codebase stays fenced exactly as shipped.
