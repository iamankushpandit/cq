# Phase-1 Selective Disclosure Infrastructure for GDPR-Oriented Workflows

**Issue:** [#140 — Design and implement zero knowledge proof for GDPR compliance](https://github.com/mozilla-ai/cq/issues/140)
**Author:** (contributor name)
**Date:** 2026-03-29
**Status:** Draft — awaiting maintainer review

### Executive Summary

- **Problem:** KUs contain sensitive provenance metadata. Consumers and auditors need to verify KU integrity without seeing every field.
- **Phase 1 mechanism:** SHA-256 hash-commitment with selective disclosure, behind a swappable `ZKPProvider` interface (not a true ZKP — Midnight replaces this in Phase 2).
- **What exists:** Provider abstraction, graduation auto-commit, 3 REST endpoints, 3 MCP tools, UI badge, 349 passing tests — all on the working branch.
- **Decisions needed:** 6 concrete maintainer decisions at the top of this document (D1–D6).
- **What ships next:** 3 PRs — (1) design doc + abstraction, (2) lifecycle + rich states, (3) API/UI surface.
- **Biggest trade-off:** Server-side salt storage (simpler, but single trust domain) — replaced by on-chain proofs in Phase 2.

> **Note on scope:** Phase 1 implements a hash-commitment selective disclosure scheme — not a true zero-knowledge proof. It provides binding, hiding, and selective disclosure using standard-library SHA-256 behind a `ZKPProvider` interface designed for drop-in replacement by Midnight's ZKP infrastructure in Phase 2. This document uses "ZKP" as the project-level label for the privacy layer, matching the architecture doc and issue #140, while being precise about what Phase 1 actually delivers.

---

## My Understanding of Scope

Phase 1 adds proof-backed integrity and selective-disclosure metadata to knowledge units at graduation, then surfaces that proof state during retrieval and review. It lets a consumer verify that specific KU fields are authentic without seeing the rest, and it detects post-graduation tampering. It is not a general model-training compliance framework, and it does not by itself establish GDPR compliance — that also requires organisational and procedural controls outside the scope of this system. If this understanding is wrong, please flag it so we can adjust the document before going further.

---

## Decisions Requested from Maintainers

Before continuing implementation beyond the existing prototype, I need maintainer sign-off on these six decisions. Each includes my recommended default and the alternative. If no objection is raised, I will proceed with the recommended option.

| # | Decision | Recommendation | Alternative | Why |
|---|---|---|---|---|
| **D1** | Proof generation failure during `approve_unit()` | **Lenient:** approval succeeds, proof is missing, warning logged | Strict: roll back approval on commitment failure | Blocking approval for a PoC privacy feature risks disrupting the core review workflow. Lenient lets us ship safely; strict can be revisited when Midnight is integrated and proofs are mandatory. |
| **D2** | Retrieval-time verification strategy | **Cached with 24-hour staleness:** verify once, cache result, re-verify when stale | Verify on every read | Prototype testing suggests per-read verification overhead is low (see [Section 16](#16-performance-and-observability) for non-benchmark estimates). Cached verification with a configurable threshold keeps that cost negligible, still catches tampering within 24h, and avoids unnecessary overhead for the PoC. |
| **D3** | Salt ownership model (Phase 1) | **Server-side storage:** salts persisted in `commitments` table alongside KU | Client-held salts: return to committer only, do not persist | Server-side is simpler for PoC: the team API can generate disclosure proofs for any committed KU without requiring the original committer. Downside: the server is a single trust domain. Phase 2 Midnight integration is expected to reduce or change this concern, depending on the final on-chain proof model. |
| **D4** | PR packaging | **Three PRs:** (1) design doc + provider abstraction, (2) lifecycle + schema, (3) API/UI surface | Single PR with everything | Three PRs align with the contributing guide's preference for well-scoped changes. Each PR is independently reviewable and mergeable. |
| **D5** | KU mutation after commitment | **Detect-and-flag:** mutations to *committed* fields (e.g. `insight.*`, `evidence.confidence`) cause retrieval verification to return `"failed"`, surfaced to consumers; mutations to non-committed fields (`status`, `flags`) have no effect on proof state; no auto-regeneration in Phase 1 | Auto-regenerate commitment on every mutation | Detect-and-flag is simpler, makes mutation visible rather than silently patching it, and avoids re-commitment overhead. Non-committed fields are deliberately excluded so normal lifecycle operations (confirmation, flagging) never invalidate proofs. Auto-regeneration is Phase 3. |
| **D6** | Committed field set | **Current 7 fields** (see [Field Selection Rationale](#12-field-selection-rationale-and-versioning)) | Broader or narrower set | These 7 fields cover identity (`created_by`), content (`insight.*`), context, domain classification, and trust signal (`evidence.confidence`). See rationale section for justification and versioning strategy. |

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Canonical Proof-State Model](#2-canonical-proof-state-model)
3. [What Is Being Proved](#3-what-is-being-proved)
4. [Current Implementation Status](#4-current-implementation-status)
5. [Architecture Overview](#5-architecture-overview)
6. [Proof Contract](#6-proof-contract)
7. [Provider Abstraction](#7-provider-abstraction)
8. [Schema Changes](#8-schema-changes)
9. [Lifecycle Integration Points](#9-lifecycle-integration-points)
10. [API Surface Changes](#10-api-surface-changes)
11. [UI Changes](#11-ui-changes)
12. [Field Selection Rationale and Versioning](#12-field-selection-rationale-and-versioning)
13. [Mutation After Commitment](#13-mutation-after-commitment)
14. [Migration and Rollback Plan](#14-migration-and-rollback-plan)
15. [Authorization and Audit Model](#15-authorization-and-audit-model)
16. [Performance and Observability](#16-performance-and-observability)
17. [Phased Implementation Plan](#17-phased-implementation-plan)
18. [Testing Strategy](#18-testing-strategy)
19. [PR Packaging Plan](#19-pr-packaging-plan)
20. [Security Considerations](#20-security-considerations)
21. [Open Questions for Maintainers](#21-open-questions-for-maintainers)
- [Appendix A: File Inventory](#appendix-a-file-inventory)
- [Appendix B: Example API Payloads](#appendix-b-example-api-payloads)

---

## 1. Motivation

The cq architecture document states:

> **Privacy layer (future work):** Midnight's zero-knowledge proof infrastructure enables selective disclosure — agents can prove a learning is valid without revealing the underlying details. This is designed but not yet implemented.

GDPR's data minimisation principle (Article 5(1)(c)) requires that only the data necessary for a specific purpose is processed. When a knowledge unit (KU) contains contributor identity, organisational context, or other sensitive provenance metadata, a consumer or auditor should be able to verify that the KU is valid and trustworthy **without accessing fields irrelevant to their purpose**.

Selective disclosure solves this: a prover can reveal any subset of a KU's fields while keeping the rest hidden behind a cryptographic commitment. A verifier checks the proof against the published commitment root to confirm the disclosed fields are authentic — without ever seeing the withheld data.

### Goals

- Build privacy-preserving selective disclosure infrastructure that supports GDPR-oriented workflows (the infrastructure itself does not constitute GDPR compliance, which also requires organisational and procedural controls).
- Integrate proof generation and verification into the existing KU lifecycle (graduation, retrieval).
- Keep the cryptographic backend swappable so the project can move from a PoC hash-commitment scheme to Midnight's ZKP infrastructure.
- Surface proof status in APIs and the review UI so humans and agents can make trust decisions.

### Non-Goals (Phase 1)

- Full Midnight ZKP integration (Phase 2).
- Proof of deletion or data minimisation claims.
- Cross-tier proof portability (Local → Team → Global proof chains).
- Automated compliance reporting.

---

## 2. Canonical Proof-State Model

Every KU has exactly one proof state at any point in time. This table is the single source of truth — all storage fields, API responses, and UI badges map to exactly one of these states. No other state names are valid.

| State | Stored `commitment_root` | Stored `proof_verification_result` | Stored `proof_verified_at` | API `proof_status` | UI Badge | Meaning |
|---|---|---|---|---|---|---|
| **none** | `NULL` | `NULL` | `NULL` | `"none"` | *(hidden)* | No commitment has ever been generated for this KU. |
| **committed** | non-null hex | `NULL` | `NULL` | `"committed"` | 🛡 Committed (gray) | Commitment exists but has never been verified against current data. |
| **verified** | non-null hex | `"verified"` | recent ISO 8601 | `"verified"` | ✓ Verified (green) | Commitment was verified and root matched current data. |
| **failed** | non-null hex | `"failed"` | recent ISO 8601 | `"failed"` | ✗ Failed (red) | Verification ran but root did not match — data may have changed since commitment. |
| **stale** | non-null hex | `"verified"` | old ISO 8601 (> threshold) | `"stale"` | ⟳ Stale (amber) | Previous verification passed but is older than the staleness threshold. Re-verification needed. |

> **Note on `"stale"`:** `"stale"` does not mean invalid or suspected-tampered. It means *previously verified successfully, but freshness assurance has expired.* A stale KU will be re-verified on its next retrieval and will transition back to `"verified"` or to `"failed"`.

### State Transitions

```
[no commitment]
        │
        │ approve_unit() → create_commitment()
        ▼
    committed
        │
        │ retrieval triggers verify_commitment_integrity()
        ├────── root matches ──────► verified
        │                                │
        │                                │ time > staleness_threshold
        │                                ▼
        │                             stale
        │                                │
        │                                │ re-verify on next access
        │                                ├── match ──► verified
        │                                └── mismatch ► failed
        │
        └────── root mismatch ─────► failed
```

### Forbidden Aliases

The following terms MUST NOT appear in code, API payloads, or documentation as state names: `"valid"`, `"invalid"`, `"ok"`, `"error"`, `"unknown"`, `"pending"`, `"expired"`. Use only the five canonical states above.

> **Internal verification failure:** If retrieval-time verification cannot complete due to an internal error (malformed commitment, deserialization bug, missing field), Phase 1 does **not** introduce a sixth state. Instead it logs a `WARNING`, preserves the last known state unchanged, and returns the retrieval successfully. See [Section 9.2](#92-retrieval-verification-proposed--phase-1) for the full rule.

### Derivation Rules

The API `proof_status` is **derived** at response time, not stored directly:

```python
def derive_proof_status(ku: KnowledgeUnit, staleness_threshold_hours: int = 24) -> str:
    if ku.commitment_root is None:
        return "none"
    if ku.proof_verification_result is None:
        return "committed"
    if ku.proof_verification_result == "failed":
        return "failed"
    # verification_result == "verified"
    if _is_stale(ku.proof_verified_at, staleness_threshold_hours):
        return "stale"
    return "verified"
```

---

## 3. What Is Being Proved

### Compliance Claim

> "The disclosed fields of this knowledge unit are the authentic, unaltered values that were committed at the time of graduation, and no other fields have been revealed."

### Formal Definition

| Property | Description |
|---|---|
| **Public inputs** | `commitment_root` (published on the KU), `disclosed_fields` (field names + values), `disclosed_salts` (per-field random salts for disclosed fields), `undisclosed_leaves` (opaque SHA-256 hashes for hidden fields) |
| **Private inputs** | Salts and field values for undisclosed fields (held only by the commitment creator) |
| **Verification success** | Recomputed root from disclosed leaves + undisclosed leaf hashes matches the published `commitment_root` |
| **Binding** | The committer cannot change any field value after commitment without invalidating the root |
| **Hiding** | Undisclosed fields are hidden behind SHA-256 with 256-bit random salts — computationally infeasible to recover |
| **Selective disclosure** | Any subset of the 7 committed fields can be independently revealed |

### Committed Fields

The following 7 KU fields are committed (sorted alphabetically for deterministic leaf ordering):

| Field | Source | Canonical Serialisation |
|---|---|---|
| `context` | `unit.context` | JSON with sorted keys, compact separators |
| `created_by` | `unit.created_by` | Raw string |
| `domain` | `unit.domain` | JSON array, sorted, compact separators |
| `evidence.confidence` | `unit.evidence.confidence` | String representation of float |
| `insight.action` | `unit.insight.action` | Raw string |
| `insight.detail` | `unit.insight.detail` | Raw string |
| `insight.summary` | `unit.insight.summary` | Raw string |

#### Canonical Serialization Rules

These rules define how each field type is converted to a string before hashing. They must be followed exactly to produce deterministic leaf values:

| Rule | Specification |
|---|---|
| **Strings** | Used as-is (UTF-8 bytes). No trimming, no Unicode normalization. Empty string `""` is valid. |
| **Floats** | Python `str()` representation (e.g. `0.85` → `"0.85"`). No fixed-decimal formatting. |
| **JSON objects** (`context`) | `json.dumps(obj, separators=(",", ":"), sort_keys=True)` — compact, keys sorted alphabetically. |
| **JSON arrays** (`domain`) | `json.dumps(sorted(arr), separators=(",", ":"))` — elements sorted alphabetically, compact. |
| **Null / missing fields** | Not supported in Phase 1. All 7 committed fields must be present and non-null at commitment time. A missing field causes `create_commitment()` to raise `ValueError`. |
| **Ordering** | Fields are always processed in alphabetical order by field name. Leaf concatenation for root computation follows the same order. |

#### Test Vector

Given the following KU fragment:

```json
{
  "context": {"project": "acme", "language": "python"},
  "created_by": "alice",
  "domain": ["api", "payments"],
  "evidence": {"confidence": 0.85},
  "insight": {
    "summary": "Stripe returns 200 for rate limits",
    "detail": "Response body contains error object despite 200 status",
    "action": "Check response body, not just status code"
  }
}
```

Canonical serialized values (in field-alphabetical order):

| Field | Canonical String |
|---|---|
| `context` | `{"language":"python","project":"acme"}` |
| `created_by` | `alice` |
| `domain` | `["api","payments"]` |
| `evidence.confidence` | `0.85` |
| `insight.action` | `Check response body, not just status code` |
| `insight.detail` | `Response body contains error object despite 200 status` |
| `insight.summary` | `Stripe returns 200 for rate limits` |

Each leaf is then `SHA-256(salt ‖ field_name ‖ canonical_string)`. The root is `SHA-256(leaf_context ‖ leaf_created_by ‖ … ‖ leaf_insight.summary)`. Any implementation that produces different canonical strings for these inputs is incompatible.

#### Negative Test Vector (Incompatible Serialization)

The following variations of the same input data produce **different** canonical strings and therefore different roots. Any implementation that produces these is broken:

| Field | Wrong Serialization | Why It Fails |
|---|---|---|
| `context` | `{"project": "acme", "language": "python"}` | Keys not sorted; contains spaces after separators |
| `domain` | `["payments","api"]` | Elements not sorted alphabetically |
| `evidence.confidence` | `0.850` | Trailing zero; Python `str(0.85)` produces `"0.85"` |
| `insight.summary` | `Stripe returns 200 for rate limits ` | Trailing whitespace; strings are used as-is, so source data must not have been trimmed |

### Failure Modes

| Failure | Cause | Behaviour |
|---|---|---|
| **Tampered disclosed value** | A disclosed field value was modified after commitment | Verification returns `false` — recomputed leaf hash does not match |
| **Tampered root** | The commitment root was altered | Verification returns `false` — recomputed root does not match supplied root |
| **Missing salt** | A disclosed field's salt is absent from the proof | Verification returns `false` — cannot recompute leaf |
| **Incomplete coverage** | Proof does not account for all 7 committed fields | Verification returns `false` — field set mismatch |
| **Wrong KU binding** | Proof was generated from a different KU's commitment | Verification returns `false` — root mismatch |
| **No commitment exists** | KU was never committed (e.g. pre-migration KU) | `proof_status = "none"` — verification not applicable |
| **Provider failure** | Proof generation fails (e.g. missing fields, provider error) | HTTP error surfaced; KU is still approved but `proof_status = "none"` |

### What This Does Not Prove

Phase 1 proves a narrow claim: **the disclosed fields of a KU match what was committed at graduation**. It does **not** prove:

> **Important:** A `"verified"` proof means the KU's committed fields still match the graduation-time snapshot. It does **not** mean the data is globally correct, current, or the best available business truth. A legitimate post-graduation update will cause `"failed"`, which is expected behavior — not evidence of wrongdoing. Downstream systems should not use proof state as a proxy for semantic quality, business correctness, or reviewer approval — it attests only to field-level integrity relative to the committed snapshot.

- **Lawful basis for processing.** Whether the organisation has a legal basis under GDPR Article 6 to process the data in the KU.
- **User consent.** Whether a data subject consented to their data being included in the knowledge system.
- **Deletion or erasure.** Whether data was actually deleted in response to a right-to-erasure request (Phase 2 goal).
- **Model-training provenance.** Whether a KU was used correctly during model training, fine-tuning, or inference.
- **Data minimisation compliance.** Whether only the minimum necessary data was collected or stored.
- **Cross-system integrity.** Whether the KU's data matches an external source of truth outside CQ.

This system provides one building block — field-level integrity and selective disclosure — within a broader GDPR compliance programme that must also include organisational policies, data-subject rights workflows, and legal review.

---

## 4. Current Implementation Status

The following work has been completed as an exploratory prototype. This design document seeks maintainer alignment before continuing.

### What Exists

| Component | File(s) | What's Done |
|---|---|---|
| **Hash-commitment crypto** | `team-api/.../zkp.py`, `plugins/.../zkp.py` | SHA-256 salted leaf hashes, root computation, selective disclosure proof generation and verification |
| **ZKPProvider protocol** | Same files | `ZKPProvider` Protocol class with `create_commitment`, `create_disclosure_proof`, `verify_disclosure_proof`. `HashCommitmentProvider` as default. `get_provider()`/`set_provider()` for backend swap |
| **REST endpoints** | `team-api/.../zkp_routes.py` | `POST /zkp/commit/{unit_id}`, `POST /zkp/disclose/{unit_id}`, `POST /zkp/verify` |
| **MCP tools** | `plugins/.../server.py` | `zkp_commit`, `zkp_disclose`, `zkp_verify` tools |
| **Schema/storage** | `team-api/.../tables.py`, `store.py`, `local_store.py` | `commitments` table (FK to KU), `commitment_root` column on `knowledge_units`, `store_commitment()`, `get_commitment()`, `has_commitment()` |
| **Graduation integration** | `team-api/.../review.py` | `approve_unit()` auto-generates a commitment on approval |
| **KU model** | `team-api/.../knowledge_unit.py` | `commitment_root: str \| None = None` |
| **API responses** | `team-api/.../review.py` | `ReviewItem.proof_status` field (`"committed"` or `"none"`) on queue, list, and detail endpoints |
| **UI badge** | `team-ui/.../ReviewCard.tsx` | Shield icon shown when `proof_status === "committed"` |
| **Tests** | Both test suites | 38 ZKP-specific tests (27 team-api, 11 plugin). 349 total tests pass |

### What's Missing

| Gap | Description | Addressed by |
|---|---|---|
| **Design doc** | No formal proof contract or design note | This document |
| **Active re-verification** | No automatic proof check at retrieval; only `"committed"` / `"none"` states | Phase 1 Story 6 |
| **Rich proof metadata** | No `provider`, `last_verified_at`, `verification_result` on KU model | Phase 1 Story 5 |
| **Richer proof states** | Only `"committed"` / `"none"` — need `"verified"`, `"failed"`, `"stale"` | Phase 1 Story 6 |
| **Rich API status block** | No `provider`/`last_verified_at` in responses | Phase 1 Story 7 |
| **Full UI states** | Only 2 of 5 visual states rendered | Phase 1 Story 8 |
| **Lint validation** | `make lint` not verified | Phase 1 Story 9 |
| **Maintainer alignment** | No discussion on #140 | Phase 1 Story 0 |

---

## 5. Architecture Overview

### Where ZKP Fits in the System

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude Code Process                       │
│  SKILL.md instructs agent: query → act → propose → reflect  │
└──────────────────────┬──────────────────────────────────────┘
                       │ stdio / MCP
┌──────────────────────▼──────────────────────────────────────┐
│                    MCP Server Process                        │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────────────┐   │
│  │ query    │  │ propose  │  │ zkp_commit              │   │
│  │ confirm  │  │ flag     │  │ zkp_disclose            │   │
│  │ reflect  │  │ status   │  │ zkp_verify              │   │
│  └──────────┘  └──────────┘  └─────────────────────────┘   │
│  ┌────────────────┐  ┌──────────────────────────────────┐   │
│  │ LocalStore     │  │ ZKPProvider (HashCommitment)     │   │
│  │ local.db       │  │   → swappable to Midnight        │   │
│  └────────────────┘  └──────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP / REST
┌──────────────────────▼──────────────────────────────────────┐
│                    Team API (Docker)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ /review/*    │  │ /query       │  │ /zkp/*          │   │
│  │ approve →    │  │ returns KUs  │  │ commit, disclose│   │
│  │  auto-commit │  │ with proof   │  │ verify          │   │
│  └──────────────┘  │ status       │  └─────────────────┘   │
│                     └──────────────┘                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ TeamStore (SQLite)                                     │  │
│  │ knowledge_units: commitment_root, proof_provider, ...  │  │
│  │ commitments: unit_id → serialised commitment           │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

> **Concurrency note:** Phase 1 relies on SQLite WAL mode for write serialization. Concurrent reads and writes to the same KU are safe because SQLite WAL provides snapshot isolation for readers and serializes writers. This is a property of the current storage backend, not the general design. If the backend changes (e.g. to PostgreSQL), concurrency guarantees must be re-evaluated for the new isolation model.

### Proof Lifecycle Sequence

```
 Proposer              Team API              Reviewer            Consumer
    │                     │                     │                    │
    │  POST /propose      │                     │                    │
    │────────────────────>│                     │                    │
    │  KU created         │                     │                    │
    │  (status=pending)   │                     │                    │
    │                     │                     │                    │
    │                     │  GET /review/queue   │                    │
    │                     │<────────────────────│                    │
    │                     │  items (no proof)   │                    │
    │                     │────────────────────>│                    │
    │                     │                     │                    │
    │                     │  POST /{id}/approve │                    │
    │                     │<────────────────────│                    │
    │                     │                     │                    │
    │                     │  [auto]             │                    │
    │                     │  create_commitment()│                    │
    │                     │  store_commitment() │                    │
    │                     │  (proof_status =    │                    │
    │                     │   "committed")      │                    │
    │                     │                     │                    │
    │                     │                     │                    │
    │                     │  GET /query?domain=…│                    │
    │                     │<────────────────────────────────────────│
    │                     │                     │                    │
    │                     │  [auto] verify      │                    │
    │                     │  commitment against │                    │
    │                     │  current KU data    │                    │
    │                     │                     │                    │
    │                     │  KU + proof_status  │                    │
    │                     │  ("verified" /      │                    │
    │                     │   "failed" / "none")│                    │
    │                     │────────────────────────────────────────>│
    │                     │                     │                    │
    │                     │  POST /zkp/disclose │                    │
    │                     │<────────────────────────────────────────│
    │                     │  disclosure proof   │                    │
    │                     │  (selected fields)  │                    │
    │                     │────────────────────────────────────────>│
    │                     │                     │                    │
    │                     │  POST /zkp/verify   │                    │
    │                     │<────────────────────────────────────────│
    │                     │  {valid: true}      │                    │
    │                     │────────────────────────────────────────>│
```

### End-to-End Scenario

A concrete walkthrough of the full proof lifecycle:

1. **Agent proposes a KU.** An AI agent calls `POST /propose` with a KU about Stripe rate-limit behaviour. The KU enters the review queue with `proof_status = "none"`.

2. **Reviewer approves.** Alice calls `POST /review/{id}/approve`. The API sets status to `"approved"`, then auto-calls `create_commitment(unit)`. The 7 committed fields are hashed with random salts, a root is computed, and the commitment (including salts) is stored in the `commitments` table. The KU's `commitment_root` column is set. `proof_status` is now `"committed"`.

3. **Consumer queries.** A different agent calls `GET /query?domain=api`. The API fetches the KU, finds a commitment, and runs `verify_commitment_integrity()` — recomputing the root from current field values. The roots match, so `proof_verification_result = "verified"` and `proof_verified_at` is set to now. Response includes `proof_status: "verified"`.

4. **Consumer requests selective disclosure.** The agent only needs `insight.summary` and `domain` for its task. It calls `POST /zkp/disclose/{id}` with `fields: ["insight.summary", "domain"]`. The API returns a proof containing the two field values, their salts, and opaque leaf hashes for the other 5 fields.

5. **Consumer verifies.** The agent (or a third party, within a CQ-controlled or trusted integration context) calls `POST /zkp/verify` with the proof. The verifier recomputes the two disclosed leaves, combines them with the 5 undisclosed leaf hashes, derives the root, and confirms it matches. Response: `{valid: true}`. The consumer now knows `insight.summary` and `domain` are authentic without ever seeing `created_by`, `context`, `evidence.confidence`, etc.

6. **Time passes.** 25 hours later, another consumer queries the same KU. The cached verification is now older than the 24-hour staleness threshold, so `proof_status = "stale"`. The API re-runs `verify_commitment_integrity()`, roots still match, and `proof_status` updates back to `"verified"`.

7. **Tampering detected (hypothetical).** If someone had modified `insight.summary` in the database between steps 3 and 6, the recomputed root would not match the stored `commitment_root`. The API would set `proof_status = "failed"`, and the consumer would see a red badge in the UI.

### Reviewer-Centered Scenario

1. **Alice opens the review queue.** She sees 5 KUs awaiting review. Three have no proof badge (`"none"` — they were proposed but not yet approved). Two were previously approved and show ✓ Verified (green).

2. **Alice approves a new KU.** After clicking approve, the KU's badge changes from no badge to 🛡 Committed (gray). It will auto-verify on the next retrieval.

3. **Next morning, Alice checks the dashboard.** One of the previously-verified KUs now shows ✗ Failed (red). She hovers over the badge and sees: "Proof verification failed — data may have been tampered." 

4. **Alice investigates.** She checks the KU's history and finds that a script modified `evidence.confidence` post-graduation (a calibration update). The original commitment no longer matches. She confirms the new value is correct and calls `POST /zkp/commit/{unit_id}` to re-commit with the current data. The badge resets to 🛡 Committed (gray), and the next retrieval will re-verify it.

5. **Meanwhile, another KU shows ⟳ Stale (amber).** This just means the last verification was over 24 hours ago. Alice takes no action — the next query will auto-re-verify and the badge will return to ✓ Verified (green) if the data is intact.

---

## 6. Proof Contract

### Phase 1: Hash-Commitment Provider (PoC)

**This is not a true zero-knowledge proof.** It is a cryptographic commitment scheme with selective disclosure properties that satisfies the same interface the Midnight ZKP backend will implement. This approach provides:

- **Binding + hiding + selective disclosure** using standard-library SHA-256.
- **No new dependencies** — important for a first PR.
- **The same ZKPProvider interface** that Midnight will implement.

#### Algorithm

```
For each of the 7 committed fields:
    salt = random 256-bit hex string
    leaf = SHA-256(salt ‖ field_name ‖ canonical_value)

root = SHA-256(leaf_context ‖ leaf_created_by ‖ ... ‖ leaf_insight.summary)
       (leaves concatenated in alphabetical field order)
```

#### Selective Disclosure

To disclose fields {F₁, F₂} from 7 total:

```
Proof = {
    root:               "abc123..."          (public: published on KU)
    disclosed:          {F₁: value, F₂: value}
    disclosed_salts:    {F₁: salt,  F₂: salt}
    undisclosed_leaves: {F₃: leaf, F₄: leaf, F₅: leaf, F₆: leaf, F₇: leaf}
}
```

Verifier recomputes:
1. For each disclosed field: `leaf_Fᵢ = SHA-256(salt ‖ field_name ‖ value)`
2. For each undisclosed field: accept the opaque leaf hash as-is
3. Concatenate all 7 leaves in alphabetical order
4. Compute `root' = SHA-256(concatenation)`
5. Assert `root' == proof.root` using constant-time comparison

### Phase 2: Midnight Provider (Future)

The `ZKPProvider` interface will be implemented by a `MidnightProvider` class that:
- Compiles selective disclosure circuits for KU field subsets.
- Generates proofs via Midnight's SDK.
- Verifies proofs on-chain or via Midnight's verification API.
- Reports capabilities via `describe_capabilities()`.

The interface is identical. Call sites do not change.

---

## 7. Provider Abstraction

### Interface (Implemented)

```python
@runtime_checkable
class ZKPProvider(Protocol):
    def create_commitment(self, unit: KnowledgeUnit) -> Commitment: ...
    def create_disclosure_proof(
        self, commitment: Commitment, unit: KnowledgeUnit,
        disclosed_fields: list[str],
    ) -> DisclosureProof: ...
    def verify_disclosure_proof(self, proof: DisclosureProof) -> bool: ...
```

### Module-Level API (Implemented)

```python
# Convenience functions delegate to the active provider singleton
create_commitment(unit)           # → Commitment
create_disclosure_proof(c, u, f)  # → DisclosureProof
verify_disclosure_proof(proof)    # → bool

get_provider()                    # → ZKPProvider
set_provider(provider)            # swap backend at runtime
```

### Injection Points

| Location | How Provider Is Used |
|---|---|
| `review.py → approve_unit()` | Calls `create_commitment()` on graduation |
| `zkp_routes.py → commit_unit()` | Calls `create_commitment()` on explicit commit |
| `zkp_routes.py → disclose_fields()` | Calls `create_disclosure_proof()` |
| `zkp_routes.py → verify_proof()` | Calls `verify_disclosure_proof()` |
| `server.py → zkp_commit` tool | Calls `create_commitment()` via MCP |
| `server.py → zkp_disclose` tool | Calls `create_disclosure_proof()` via MCP |
| `server.py → zkp_verify` tool | Calls `verify_disclosure_proof()` via MCP |
| **Phase 1 NEW** `store.py → get()` | Will call `verify_commitment_integrity()` on retrieval (not the same as `verify_disclosure_proof()` — see [Section 9.2](#92-retrieval-verification-proposed--phase-1)) |

### Why Retrieval Integrity Is Outside the Provider Contract

`verify_commitment_integrity()` is intentionally **not** a method on `ZKPProvider`. The provider contract handles *proof objects* — creating commitments, generating disclosure proofs, and verifying disclosure proofs. Retrieval verification is a different operation: it recomputes the commitment root from current KU field values and compares it against the stored root. It does not involve a proof object at all.

Keeping it separate has three benefits:
1. **Provider-agnostic.** The retrieval check works the same way regardless of whether the commitment was generated by `HashCommitmentProvider` or `MidnightProvider`, because it only relies on the deterministic root-computation algorithm, which is shared.
2. **Simpler provider interface.** Providers don't need to know about retrieval lifecycle concerns like staleness thresholds or caching.
3. **Single implementation.** The root recomputation logic lives in one place (`verify_commitment_integrity()` in `zkp.py`) rather than being duplicated across providers.

If a future provider uses a fundamentally different root-computation algorithm (e.g. Midnight uses a Merkle tree instead of flat concatenation), `verify_commitment_integrity()` will need to dispatch to provider-specific logic. At that point, adding a `verify_commitment(unit, stored_root) → bool` method to the provider protocol is the right path. Phase 1 does not need this because there is only one root-computation algorithm.

> **Phase 1 constraint:** The provider-agnostic property above holds only as long as all providers share the same root-computation algorithm. This is a Phase 1 simplification, not a general architectural guarantee. If Phase 2 introduces a provider with a different root scheme, retrieval integrity must become provider-aware.

---

## 8. Schema Changes

### Current Schema (Implemented)

```sql
-- On knowledge_units table
ALTER TABLE knowledge_units ADD COLUMN commitment_root TEXT;

-- Separate commitments table
CREATE TABLE IF NOT EXISTS commitments (
    unit_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,   -- JSON-serialised Commitment (includes salts)
    FOREIGN KEY (unit_id) REFERENCES knowledge_units(id) ON DELETE CASCADE
);
```

### Proposed Schema Additions (Phase 1 — Not Yet Implemented)

```sql
ALTER TABLE knowledge_units ADD COLUMN proof_provider TEXT;
ALTER TABLE knowledge_units ADD COLUMN proof_verified_at TEXT;
ALTER TABLE knowledge_units ADD COLUMN proof_verification_result TEXT;

-- commitments table gains a timestamp
ALTER TABLE commitments ADD COLUMN created_at TEXT;
```

### KnowledgeUnit Model Changes (Proposed)

```python
class KnowledgeUnit(BaseModel):
    # ... existing fields ...
    commitment_root: str | None = None          # ← exists
    proof_provider: str | None = None           # ← new: "hash-commitment" | "midnight"
    proof_verified_at: str | None = None        # ← new: ISO 8601 timestamp
    proof_verification_result: str | None = None  # ← new: "verified" | "failed" | None
```

All new fields default to `None`, ensuring backward compatibility with existing KUs.

**`proof_provider` semantics:** This field records **the provider that produced the currently stored commitment** — not the system's current default provider, and not the provider used for the last verification. If the system provider changes (e.g. from `"hash-commitment"` to `"midnight"`), existing KUs retain their original `proof_provider` until they are re-committed.

**Mixed-provider coexistence (Phase 2 transition):** When a Phase 2 deployment introduces `MidnightProvider` alongside the existing `HashCommitmentProvider`, both provider types will coexist in the same database:
- `/query` responses return KUs regardless of their `proof_provider`. The `proof_provider` field tells the consumer which scheme produced the commitment.
- Retrieval-time `verify_commitment_integrity()` must dispatch to the correct root-computation algorithm based on `proof_provider` (see the Phase 1 constraint note in [Section 7](#7-provider-abstraction)).
- Disclosure proof payloads are provider-specific — a `hash-commitment` proof and a `midnight` proof have different structures. Consumers must check `proof_provider` before interpreting the payload.
- Old `hash-commitment` KUs are never auto-migrated to `midnight`. They remain valid under their original provider until explicitly re-committed.
- **Query response shape guarantee:** Regardless of provider, all KUs expose the same top-level `proof_status`, `proof_provider`, and `proof_verified_at` fields in API responses. The proof-status shape is provider-agnostic. Only the internal disclosure proof payload (returned by `/zkp/disclose`) is provider-specific.

**`proof_provider` null edge case:** `proof_provider` can be `None` when `commitment_root` is non-null if the KU was committed by code that predates the `proof_provider` field (i.e. the existing prototype code, before Phase 1 schema additions land). The API should treat `proof_provider = None` with a non-null `commitment_root` as `"hash-commitment"` (the only provider that could have produced it). Phase 1 migration should backfill existing commitment rows with `proof_provider = "hash-commitment"`.

**Canonical API placement:** `proof_status`, `proof_provider`, and `proof_verified_at` are exposed on both `ReviewItem` responses and KU-bearing `/query` responses. The authoritative persisted fields are on the `KnowledgeUnit` model. `ReviewItem` derives its values from the KU — there is no separate truth source.

---

## 9. Lifecycle Integration Points

### 9.1 Graduation (Implemented)

**Trigger:** `POST /review/{unit_id}/approve`

**Behaviour:**
1. Review status set to `"approved"`.
2. System automatically generates a commitment via `create_commitment(unit)`.
3. Commitment is stored in `commitments` table.
4. `commitment_root` is written to the KU's JSON blob and the `commitment_root` column.

**Failure handling:** If commitment generation fails, the approval still succeeds but `proof_status` remains `"none"`. This avoids blocking the review workflow for a PoC feature. A warning is logged.

> **Phase 1 enforcement policy:** Proof state is **advisory and observable, not a hard enforcement gate.** No API endpoint, UI action, or lifecycle transition is blocked by `"failed"`, `"stale"`, or `"none"` proof status. Consumers and reviewers see the state and decide how to act on it. Although Phase 1 does not enforce proof state as a hard gate, it makes integrity visible in normal workflows and establishes the data model, API surface, and UI hooks required for future enforcement policies. If maintainers want specific gates (e.g. block graduation of previously-failed KUs), that can be added as opt-in policy in Phase 2+.

### 9.2 Retrieval Verification (Proposed — Phase 1)

**Trigger:** `GET /query?domain=...` and `GET /review/{unit_id}`

> **Important distinction:** Retrieval verification is **not** the same as `verify_disclosure_proof()`. A disclosure proof verifies a selective subset of fields against a root. Retrieval verification is a simpler integrity check: recompute the commitment root from all current KU field values and compare it against the stored `commitment_root`. The operation is `verify_commitment_integrity(unit, stored_root)`, not `verify_disclosure_proof(proof)`.

**Behaviour:**
1. After fetching a KU, check whether a commitment exists.
2. If yes, recompute the commitment root from the current KU field values using `verify_commitment_integrity()` and compare against the stored `commitment_root`.
3. Record the verification result and timestamp.

**Proof Status State Machine:**

The proof-state machine is defined in [Section 2: Canonical Proof-State Model](#2-canonical-proof-state-model). The state transitions and derivation rules are the single source of truth for all code.

**Staleness rule:** A verification result older than a configurable threshold (default: 24 hours) is marked `"stale"` and re-verified on next access. This avoids re-verifying on every single query while catching data corruption or tampering.

**Writeback semantics:** When a stale (or first-time) KU is retrieved, the API **synchronously** recomputes the commitment root, persists the updated `proof_verified_at` and `proof_verification_result`, and returns the fresh status in the response. There is no deferred or background refresh — the caller always receives the current verification result, not a stale cached value.

**Timestamp update rule:** `proof_verified_at` is written **only** when a verification actually runs — i.e. on first access after commitment, or when the previous result is stale (older than the staleness threshold). A retrieval that finds a fresh, non-stale `"verified"` result does **not** update the timestamp. This avoids write amplification on hot KUs and ensures `proof_verified_at` reflects the last actual verification, not the last read.

**Internal verification failure (cannot-run):** If retrieval-time verification cannot complete due to an internal error — malformed legacy commitment data, a deserialization bug, a missing field, or an unexpected exception — Phase 1 behaviour is:
1. Log a `WARNING` with `unit_id`, error detail, and `"verification_error": true`.
2. **Do not write** to `proof_verification_result` or `proof_verified_at` — leave them unchanged.
3. Return the **last known proof state** to the caller (e.g. `"committed"`, `"stale"`, or whatever was previously stored).
4. Do **not** surface a 5xx — the retrieval itself succeeds; only the integrity sidecar fails.

This preserves the principle that proof state is advisory and never blocks normal API operation. The logged warning ensures ops can detect and investigate broken commitments. A future phase may add a sixth state (e.g. `"error"`) if structured error reporting is needed, but Phase 1 avoids expanding the state model for an edge case.

> **Semantic meaning of `"stale"`:** `"stale"` does not mean invalid or suspected-tampered. It means *previously verified successfully, but freshness assurance has expired*. The KU may still be perfectly intact — the system simply has not re-checked recently enough to confirm. A `"stale"` KU will be re-verified on its next retrieval and will transition to `"verified"` (still intact) or `"failed"` (changed since commitment).

### 9.3 Future Integration Points (Phase 2+)

| Event | Phase | Behaviour |
|---|---|---|
| **Ingestion** | Phase 3 | Generate commitment at `POST /propose` time (before review) |
| **KU Update** | Phase 3 | Re-generate commitment when KU data changes (confirmation, flag) |
| **Deletion** | Phase 2 | Generate proof-of-deletion claim |
| **Tier promotion** | Phase 3 | Carry forward or re-generate commitment on Team → Global graduation |

---

## 10. API Surface Changes

### 10.1 Existing Endpoints — Extended (Phase 1)

**ReviewItem response** (used by `/review/queue`, `/review/units`, `/review/{unit_id}`):

```json
{
  "knowledge_unit": { "...": "...", "commitment_root": "abc123..." },
  "status": "approved",
  "reviewed_by": "alice",
  "reviewed_at": "2026-03-29T10:00:00Z",
  "proof_status": "verified",
  "proof_provider": "hash-commitment",
  "proof_verified_at": "2026-03-29T10:05:00Z"
}
```

**`/query` response** — KnowledgeUnit already includes `commitment_root`. Phase 1 adds inline verification so the consumer knows the commitment is still valid without a second round-trip.

### 10.2 ZKP-Specific Endpoints (Implemented)

> **Phase 1 proof format classification: internal.** The proof format is a **CQ-internal implementation detail**, not a trusted-team interchange format or an external compatibility promise. No consumer — internal or external — should treat the Phase 1 wire format as stable. Proof structure, field names, and serialization may change without notice between phases. The end-to-end scenario in Section 5 shows a third party verifying a proof via `POST /zkp/verify`; this demonstrates the *mechanism*, not a stability guarantee. A stable, versioned proof format suitable for external auditors or third-party integrations is a Phase 2+ deliverable.

| Endpoint | Method | Purpose |
|---|---|---|
| `/zkp/commit/{unit_id}` | POST | **Team-internal maintenance/recovery API.** Create or overwrite a commitment for a KU. Overwrites any existing commitment (see [Re-Commitment Semantics](#re-commitment-and-overwrite-semantics)). Returns the full commitment including salts. Not intended as a routine consumer action — the normal path is auto-commit on graduation. |
| `/zkp/disclose/{unit_id}` | POST | Generate a selective disclosure proof for specified fields. Requires a prior commitment. |
| `/zkp/verify` | POST | Stateless verification of a disclosure proof against its embedded root. No DB access. |

### 10.3 MCP Tools (Implemented)

| Tool | Purpose |
|---|---|
| `zkp_commit` | Create commitment from MCP client |
| `zkp_disclose` | Generate disclosure proof from MCP client |
| `zkp_verify` | Verify disclosure proof from MCP client |

### 10.4 Backward Compatibility

All new fields are optional with defaults:
- `commitment_root: str | None = None`
- `proof_status: str = "none"`
- `proof_provider: str | None = None` (proposed)
- `proof_verified_at: str | None = None` (proposed)

Existing clients that do not understand these fields can safely ignore them.

### 10.5 API Guidance for `"failed"` Proof Status

For automated consumers (agents, scripts, downstream services): Phase 1 clients should treat `"failed"` as a **high-signal warning, not an automatic rejection**, unless local policy says otherwise. The recommended behaviour is to log the failure, surface it to a human operator, and continue processing. `"failed"` means the KU's committed fields no longer match the graduation-time snapshot — it does not by itself imply malicious intent. The most common causes are benign: data migration, schema evolution, manual DB correction, or an application bug.

**Policy ownership:** CQ surfaces the integrity signal; embedding applications or operators decide enforcement. CQ does not prescribe whether `"failed"` should block downstream processing, trigger alerts, or be silently logged — that is a deployment-specific policy decision outside the scope of this design.

---

## 11. UI Changes

### Current State

The review UI (`ReviewCard.tsx`) shows a shield badge with "Proof" text when `proof_status === "committed"`. Two states: present / absent.

### Proposed: 5 Visual States

| State | Badge | Colour | Tooltip |
|---|---|---|---|
| `none` | (no badge) | — | KU has no proof commitment |
| `committed` | 🛡 Committed | Gray | Commitment exists, not yet verified |
| `verified` | ✓ Verified | Green | Proof verified against current data |
| `failed` | ✗ Failed | Red | Proof verification failed — data may have been tampered |
| `stale` | ⟳ Stale | Amber | Last verification is older than threshold |

### User Action Guidance

| State | What the reviewer / consumer should do |
|---|---|
| `none` | Normal — no proof exists for this KU. No action needed unless proof coverage is required. |
| `committed` | Proof exists but hasn't been verified yet. Will auto-verify on next retrieval. No manual action needed. |
| `verified` | Trust normally. The KU's committed fields match the graduation-time snapshot. |
| `stale` | Trust with caution. A re-verification is pending on the next retrieval. Will auto-resolve to `verified` or `failed`. |
| `failed` | **Investigate.** The KU's committed fields no longer match the graduation-time commitment. `"failed"` does not by itself imply malicious intent — the most common causes are benign: data migration, manual DB edit, schema evolution, or an application bug. Consider re-committing if the current data is correct, or escalating if tampering is suspected. |

### Implementation Approach

- `ReviewItem.proof_status` already carries the state from the API.
- `ReviewCard` maps `proof_status` to badge variant via a lookup table.
- No cryptographic internals are exposed to the UI.

---

## 12. Field Selection Rationale and Versioning

### Why These 7 Fields

The committed field set was chosen to cover three categories that matter for GDPR-oriented disclosure:

| Category | Fields | Rationale |
|---|---|---|
| **Identity** | `created_by` | Ties the KU to its author — essential for data-subject requests ("show me what was committed about my contributions"). |
| **Content** | `insight.summary`, `insight.detail`, `insight.action` | The substantive knowledge payload. If any of these change after graduation, the KU's meaning has changed and the commitment should fail verification. |
| **Context & classification** | `context`, `domain` | Determine how the KU is indexed and retrieved. Tampering with these could cause a KU to appear in the wrong domain or be suppressed. |
| **Trust signal** | `evidence.confidence` | The confidence score directly influences consumer trust decisions. Inflating it post-commitment would be a meaningful integrity violation. |

### Why Not More

- **`id`**: Immutable primary key — committing it adds no integrity value.
- **`status`**: Mutable by design (pending → approved → confirmed). Including it would cause every status change to invalidate the commitment, which conflicts with the lifecycle.
- **`flags`**: Mutable post-graduation (Phase 3 adds flag-on-mutation detection). Including flags would mean every flag addition invalidates proof, which is undesirable — flagging is a safety mechanism that should not be blocked by proof state.
- **`evidence.source`, `evidence.citations`**: These are extensive nested structures that may evolve. Phase 3 can add them once schema versioning is in place.

### Why Not Fewer

Removing any of the 7 fields would leave a meaningful gap:
- Without `created_by`: no author binding — a KU could be re-attributed.
- Without `evidence.confidence`: confidence could be silently inflated.
- Without `context`: the KU's situational grounding could be replaced.

### Versioning Strategy

When the committed field set changes (e.g. Phase 3 adds `evidence.source`):

1. Add a `commitment_version: int` field to the `Commitment` model (default: `1`).
2. The `HashCommitmentProvider.create_commitment()` method records the version.
3. Verification checks the version and applies the corresponding field set.
4. Old commitments remain valid under their original version — no retroactive invalidation.
5. New commitments use the latest version.

This avoids a "big bang" migration where all existing commitments must be regenerated.

**Serialization location:** Versioned field-set definitions and their canonical serialization logic live in **provider code** (e.g. `HashCommitmentProvider` contains a version-to-field-set mapping). They are not stored in migration scripts or ad-hoc documentation. When `verify_commitment_integrity()` encounters a commitment, it reads the `commitment_version` to determine which field set and serialization rules apply.

**Ownership rule:** Canonical serialization rules and version-specific verification logic are owned by provider/verifier code, not by migrations, API docs, or UI components. Any change to serialization rules requires a version bump — never a silent change to existing version behaviour.

---

## 13. Mutation After Commitment

### Phase 1 Rules

Once a KU is committed (i.e. `commitment_root IS NOT NULL`), the following mutation rules apply:

| Mutation | Expected? | Effect on Proof State |
|---|---|---|
| **Status change** (approved → confirmed) | Yes — normal lifecycle | No effect. `status` is not a committed field. |
| **Flag added** | Yes — safety mechanism | No effect. `flags` is not a committed field. |
| **`insight.*` edited** | Rare — should not happen post-graduation | Retrieval verification returns `"failed"`. Surfaced to consumers. |
| **`evidence.confidence` changed** | Rare — recalibration | Retrieval verification returns `"failed"`. Surfaced to consumers. |
| **`domain` changed** | Rare — reclassification | Retrieval verification returns `"failed"`. Surfaced to consumers. |
| **KU deleted** | Yes — data-subject request | Commitment row cascade-deleted. No orphan proofs. |

### Design Principles

1. **Detect, don't block.** Phase 1 does not prevent mutations — it makes them visible through verification failure. This keeps the review and lifecycle workflows unimpeded.
2. **No auto-regeneration.** If a committed field changes, the commitment becomes invalid. Phase 1 does not automatically regenerate it. The `"failed"` state is the signal. Phase 3 adds auto-regeneration.
3. **Non-committed fields are free.** Changes to `status`, `flags`, and other non-committed fields have no effect on proof state. This is intentional.

### What Consumers See

When a consumer retrieves a KU via `/query`:
- If a *committed field* was mutated after commitment, `proof_status` will be `"failed"`.
- If only non-committed fields changed (status, flags), `proof_status` is unaffected — still `"verified"` or `"committed"`.
- The consumer can still use the KU — the data is not hidden. The proof status is informational.
- The consumer (human or agent) decides how to weight a `"failed"` proof.

### Phase 3 Evolution

Phase 3 (Story 3.2) will add:
- Auto-regeneration of commitments on specific mutations (e.g. confirmation).
- Mutation audit log: which field changed, when, by whom.
- Option for reviewers to manually trigger re-commitment.

---

## 14. Migration and Rollback Plan

### Existing Data

When the Phase 1 schema migration runs, all pre-existing KUs will have:
- `commitment_root = NULL`
- `proof_provider = NULL`
- `proof_verified_at = NULL`
- `proof_verification_result = NULL`

These KUs will show `proof_status = "none"` — no commitment exists, no verification applies. This is safe and correct: they were graduated before the proof system existed.

**Migration safety:** The Phase 1 schema migration (adding columns with `NULL` defaults) is idempotent and safe to run partially. If migration is interrupted, rows that were not yet altered simply remain without the new columns, and the application code treats missing columns as `NULL`. There is no all-or-nothing requirement — partial completion leaves the database in a consistent state. Re-running the migration is harmless.

### Backfill Strategy

**Phase 1: No backfill.** Only newly-approved KUs get commitments. Existing KUs remain in `"none"` state indefinitely unless a reviewer explicitly calls `POST /zkp/commit/{unit_id}` via the API.

**Rationale:** Backfilling would generate commitments from current data, not data-at-graduation-time. These commitments would be valid but misleading — they prove the KU hasn't changed *since backfill*, not *since graduation*. Phase 3 can add an explicit backfill command with clear semantics (e.g. "re-committed at [timestamp], original graduation commitment not available").

**No-backfill policy:** Phase 1 performs no automatic or lazy backfill of existing KUs. Proof state begins only at new commitments. Old KUs remain in `"none"` state **permanently** unless an operator explicitly calls `POST /zkp/commit/{unit_id}`. There is no planned background job, migration script, or eventual-consistency process that will commit old KUs automatically.

### Rollback Procedure

If Phase 1 needs to be reverted:

1. **Remove routes:** Delete `zkp_routes.py`, remove router registration from `app.py`.
2. **Remove graduation hook:** Revert the `approve_unit()` change in `review.py` to remove auto-commit.
3. **Drop columns:** `ALTER TABLE knowledge_units DROP COLUMN commitment_root` (and proof_provider, proof_verified_at, proof_verification_result).
4. **Drop table:** `DROP TABLE commitments`.
5. **Remove model fields:** Revert `KnowledgeUnit` and `ReviewItem` changes.
6. **No data loss:** No existing data depends on proof columns. All original KU data is untouched.

The proof system is additive — it writes to new columns and a new table. Rolling back does not affect any existing data or workflows.

### SQLite Considerations

SQLite does not support `DROP COLUMN` in older versions (pre-3.35.0). If the target SQLite version is older, rollback requires:
1. Create new table without proof columns.
2. Copy data from old table.
3. Drop old table.
4. Rename new table.

This is standard for SQLite migrations and is already the pattern used elsewhere in the codebase.

---

## 15. Authorization and Audit Model

> **⚠️ Phase 1 trust assumption:** The authorization model below assumes a single trusted team domain where all authenticated users are trusted peers. It is **not suitable as-is for multi-tenant or adversarial environments.** Phase 2+ should add per-user commitment ownership and restricts who can regenerate or overwrite commitments. If CQ ships multi-tenancy before Phase 2, the auth model must be tightened first.

### Who Can Do What

| Action | Authorized Actor(s) | Auth Mechanism |
|---|---|---|
| **Generate commitment** (auto, on approve) | Any reviewer approving the KU | Implicit — `approve_unit()` triggers it |
| **Generate commitment** (explicit, via API) | Any authenticated user | `POST /zkp/commit/{unit_id}` — JWT required |
| **Generate disclosure proof** | Any authenticated user | `POST /zkp/disclose/{unit_id}` — JWT required |
| **Verify a disclosure proof** | Anyone (stateless) | `POST /zkp/verify` — no auth required (proof is self-contained) |
| **Read commitment data** (salts + leaves) | Server-side only in Phase 1 | Not exposed via API; salts returned only on `POST /zkp/commit` response |
| **Re-generate commitment** | Any authenticated user | `POST /zkp/commit/{unit_id}` overwrites existing commitment |

### Phase 1 Simplifications

- **No per-user commitment ownership.** Any authenticated user can commit any KU. This is acceptable for the PoC because the team API operates within a single trust domain (all team members are trusted).
- **Original committer is not tracked.** The `commitments` table does not record who generated the commitment. Phase 3 should add `committed_by` and `committed_at` columns.
- **Salt access is server-side.** Because salts are stored in the DB, the server can generate disclosure proofs for any committed KU. This is a Phase 1 trade-off (see Decision D3).

### Audit Logging (Phase 1)

Phase 1 logs the following at `INFO` level:

| Event | Log Message | Fields |
|---|---|---|
| Commitment generated | `"ZKP commitment created"` | `unit_id`, `provider`, `timestamp`, `actor` (if available from JWT) |
| Commitment overwritten | `"ZKP commitment created"` | `unit_id`, `provider`, `timestamp`, `actor`, `"overwrite": true` |
| Commitment generation failed | `"ZKP commitment failed"` (WARNING) | `unit_id`, `error`, `timestamp` |
| Disclosure proof generated | `"ZKP disclosure proof created"` | `unit_id`, `disclosed_fields`, `timestamp`, `actor` |
| Verification performed | `"ZKP verification result"` | `unit_id`, `valid` (bool), `timestamp` |

**Minimum audit event schema:** Every Phase 1 proof log entry must include at least the following fields. This is the interface ops tooling can depend on:

| Field | Type | Present On | Purpose |
|---|---|---|---|
| `unit_id` | string | All events | Identifies the KU |
| `timestamp` | ISO 8601 | All events | When the event occurred |
| `actor` | string \| null | Commit, disclose | Who triggered the operation (from JWT) |
| `provider` | string | Commit | Which provider produced the commitment |
| `overwrite` | bool | Commit (if overwriting) | Distinguishes new vs. replacement commitments |
| `valid` | bool | Verify | Verification outcome |
| `error` | string | Failures only | Error detail for WARNING-level events |

> **Minimum operational signal:** Every log entry includes `unit_id` and `timestamp`. `actor` (the authenticated user identity from the JWT, if available) is included for commitment and disclosure events to support after-the-fact attribution. These are the minimum fields that Phase 1 must emit; additional structured audit events are a Phase 3 deliverable.

**Minimum reconciliation capability:** From Phase 1 log signals alone, an operator must be able to answer: *"Which KUs were re-committed this week, by whom, and after how many prior verification failures?"* This requires the overwrite, actor, and verification-result fields defined above. If log aggregation is not available, the same question can be answered by querying the `commitments` table's `created_at` column and correlating with `proof_verification_result` on the KU.

### Phase 1 Trust Model Summary

Phase 1 operates under a **single-trusted-team assumption**. In plain language, this means:

- **Trust boundary:** All authenticated users with Team API access (i.e. holding a valid JWT issued by the CQ auth system) are assumed to be within the same administrative trust domain. There is no distinction between "admin" and "regular" team members for proof operations.
- Any authenticated team member can commit, re-commit, disclose, or verify any KU. There is no per-user ownership or authorization scoping.
- Server-side salt storage means the service itself can generate disclosure proofs for any committed KU — there is no holder-only secret.
- The primary safety mechanism is **auditability, not prevention**: all proof operations are logged, but nothing stops an authenticated user from overwriting a commitment or generating proofs they did not author.
- Proof state is advisory (see Section 9.1). No workflow gate blocks actions based on proof status.

This model is acceptable for a PoC within a trusted team. It becomes unacceptable the moment CQ introduces multi-tenancy, external auditors, or untrusted actors. The Phase 3 enhancements at the end of this section describe the transition path.

### Phase 1 Accepted Abuse Cases

The following abuse scenarios are **known and accepted** in Phase 1 under the single-trusted-team assumption. They become unacceptable once multi-tenancy or external actors are introduced.

| Abuse Case | Impact | Why Accepted |
|---|---|---|
| **Commitment overwrite.** Any authenticated user can call `POST /zkp/commit/{unit_id}` to replace an existing commitment, effectively resetting proof history. | Proof state is lost. A `"failed"` proof can be silently replaced with a fresh `"committed"`. | Phase 1 logs the overwrite event. Phase 3 adds `committed_by` tracking and restricts re-commitment to the original committer or an admin. |
| **Unattributed disclosure.** Any authenticated user can generate disclosure proofs for any KU, even ones they did not author or commit. | Selective disclosure is not scoped to authorship. | Acceptable in a trusted team where all members have legitimate access. Phase 3 adds per-user disclosure tracking. |
| **Salt access via DB.** Because salts are stored server-side, anyone with database access can generate arbitrary disclosure proofs. | DB compromise exposes all salt material. | Server-side storage is a PoC simplification (Decision D3). Phase 2 Midnight proofs are generated on-chain without server-held salts. |
| **Re-commitment after failure.** A user who notices a `"failed"` proof can re-commit the KU with its current (mutated) data, making the new commitment valid — but the original graduation-time commitment is lost. | Audit trail of field changes is obscured. | Phase 1 logs re-commitment. Phase 3 adds a commitment history table rather than a single active row. |

### Re-Commitment and Overwrite Semantics

> **Formal Phase 1 rule:** Re-commitment is **by design, not merely tolerated.** Any authenticated user may call `POST /zkp/commit/{unit_id}` at any time, including after a `"failed"` verification. The overwrite is expected, logged, and safe within the trusted-team model. It is the intended recovery path when KU data has legitimately changed after graduation.

> **Effect on authoritative snapshot:** A re-commitment **creates a new authoritative snapshot**, not a temporary repair. The new commitment becomes the canonical baseline for all future integrity checks. The previous commitment is permanently replaced (Phase 1) or archived (Phase 3 append-only history). Consumers should treat the current commitment as the definitive graduation-time snapshot for this KU.

`POST /zkp/commit/{unit_id}` on a KU that already has a commitment **replaces** the active commitment:
- The old commitment row is overwritten (not soft-deleted).
- `commitment_root` on the KU is updated to the new root.
- `proof_verified_at` and `proof_verification_result` are reset to `NULL` (state returns to `"committed"`).
- The overwrite is logged at `INFO` level with `unit_id` and `"overwrite": true`.

Phase 3 should change this to append-only (commitment history) rather than overwrite.

### Phase 3 Enhancements

- Add `committed_by` column to `commitments` table.
- Restrict re-commitment to the original committer or an admin.
- Emit structured audit events (not just log lines) for compliance reporting.
- Record all proof operations in a dedicated `proof_audit_log` table.
- Commitment history: append new commitments rather than overwriting.

---

## 16. Performance and Observability

### Expected Overhead (Estimates)

The following are rough estimates from the prototype on a development machine, not production benchmarks. Actual performance may differ under load or on different hardware.

| Operation | Estimated Time | Acceptable Threshold |
|---|---|---|
| `create_commitment()` | < 1 ms (7 SHA-256 hashes + 1 root hash) | 5 ms |
| `create_disclosure_proof()` | < 1 ms (subset of hashes + assembly) | 5 ms |
| `verify_disclosure_proof()` | < 1 ms (recompute + compare) | 5 ms |  
| `verify_commitment_integrity()` | < 1 ms (recompute root from KU fields, compare) | 5 ms |
| Retrieval with cached verification | 0 ms (read from DB) | 0 ms |
| Retrieval with live verification | < 1 ms (1 verify) | 10 ms per KU |

SHA-256 is CPU-bound but extremely fast for 7 small fields. Even at 1000 KUs, a full verification sweep is estimated to take < 1 second. These estimates should be validated with a proper benchmark (Phase 4, Story 4.1) before relying on them at scale.

**Proof-size growth:** Disclosure proof payload size grows linearly with the number of committed fields: each disclosed field adds a value + salt pair, and each undisclosed field adds a leaf hash. With 7 fields this is negligible (< 2 KB per proof). If the committed field set expands significantly in future versions, payload size should be monitored — this naturally motivates the versioning strategy in [Section 12](#12-field-selection-rationale-and-versioning).

### Caching Strategy

Verification results are persisted in the KU model (`proof_verified_at`, `proof_verification_result`). This means:
- **First retrieval after commitment:** live verification, result cached.
- **Subsequent retrievals within staleness window:** cached result returned, no re-verification.
- **After staleness window:** re-verify on next access, update cache.

This is a **write-through cache** — the verification result is always the true result of the last check. There is no separate cache layer to invalidate.

### Metrics to Emit (Phase 1)

| Metric | Type | Description |
|---|---|---|
| `zkp_commitments_created_total` | Counter | Total commitments generated |
| `zkp_verification_results` | Counter (labels: `result=verified\|failed`) | Verification outcomes |
| `zkp_verification_duration_seconds` | Histogram | Time spent in `verify_disclosure_proof()` or `verify_commitment_integrity()` |
| `zkp_proof_status_distribution` | Gauge (labels: `status=none\|committed\|verified\|failed\|stale`) | Current proof state distribution across all KUs |

**Implementation:** Metrics are emitted via Python `logging` in Phase 1 (structured JSON logs). Phase 2+ can switch to Prometheus client if a metrics endpoint is added.

### Observability Gaps (Acceptable in Phase 1)

- No dashboard or alerting. Metrics are in logs only.
- No bulk verification endpoint (verify all KUs at once). Can be scripted via the existing API.
- No proof-coverage percentage visible to users. Phase 4 (Story 4.2) adds a compliance dashboard.

---

## 17. Phased Implementation Plan

### Phase 1: Foundational Integration (Current Focus)

| Story | Description | Status | Depends On |
|---|---|---|---|
| **0** | Post phased plan on #140, seek maintainer alignment | ❌ Not done | — |
| **1** | This design document | ✅ This document | Story 0 |
| **2** | ZKPProvider protocol + HashCommitmentProvider | ✅ Done | — |
| **3** | Generate commitment at graduation boundary | ✅ Done | Story 2 |
| **4** | Persist proof metadata (provider, timestamps, verification result) | ⚠️ Partial | Story 2 |
| **5** | Auto-verify on retrieval (verified/failed/stale states) | ❌ Not done | Story 4 |
| **6** | Expose rich proof status in API responses | ⚠️ Partial | Story 5 |
| **7** | Update review UI for all 5 proof states | ⚠️ Partial | Story 6 |
| **8** | Tests, `make lint`, PR packaging | ⚠️ Partial | All above |

### Phase 2: Advanced ZKP Integration

| Story | Description |
|---|---|
| **2.1** | Evaluate Midnight SDK and proof compilation for selective disclosure circuits |
| **2.2** | Implement `MidnightProvider` conforming to `ZKPProvider` protocol |
| **2.3** | Add `describe_capabilities()` to provider interface for feature detection |
| **2.4** | Add fine-grained claims: proof of deletion, data minimisation attestation |
| **2.5** | Integrate verification at additional lifecycle events (ingestion guardrails) |

### Phase 3: Lifecycle Coverage & Flexibility

| Story | Description |
|---|---|
| **3.1** | Generate commitments at ingestion (`POST /propose`) |
| **3.2** | Re-generate commitments on KU mutation (confirmation, flag, update) |
| **3.3** | Implement proof expiration and automatic re-verification schedules |
| **3.4** | Allow per-domain or per-tier proof scheme configuration |
| **3.5** | Carry forward or re-generate proofs on Team → Global promotion |

### Phase 4: Scalability & Usability

| Story | Description |
|---|---|
| **4.1** | Benchmark and optimise proof generation/verification at scale |
| **4.2** | Add compliance dashboard section (proof coverage %, verification failure rates) |
| **4.3** | Automated GDPR audit report generation based on proof states |
| **4.4** | Modular proof policy engine (select scheme per regulation or data classification) |

---

## 18. Testing Strategy

### Existing Tests (38 ZKP-specific, 349 total)

**team-api (27 tests):**
- `TestCreateCommitment`: commitment generation, determinism, salt uniqueness
- `TestCreateDisclosureProof`: single field, multiple fields, all fields, zero fields, invalid fields
- `TestVerifyDisclosureProof`: valid proofs, tampered values, tampered roots, missing salts, tampered leaves, missing fields
- `TestZkpCommitEndpoint`: API commit, 404, root storage
- `TestZkpDiscloseEndpoint`: API disclose, no commitment 409, invalid fields, 404
- `TestZkpVerifyEndpoint`: API verify valid, API verify tampered

**plugin (11 tests):**
- `TestCommitmentRoundTrip`: single field, all fields, zero fields, tampered value, tampered salt, cross-unit rejection
- `TestLocalStoreCommitments`: store/retrieve, not found, missing unit error, overwrite, delete cascade

### Planned Additional Tests (Phase 1)

| Area | Tests |
|---|---|
| **Provider abstraction** | `set_provider()` swaps backend; custom provider used for commit/verify; reset to default |
| **Graduation auto-commit** | Approve generates commitment; commitment root in KU JSON; reject does not commit |
| **Retrieval verification** | Query returns `"verified"` for valid commitment; `"failed"` for tampered KU; `"stale"` for old verification; `"none"` for no commitment |
| **Schema migration** | New columns added correctly; existing data backward-compatible |
| **API proof status** | ReviewItem includes correct proof_status, proof_provider, proof_verified_at in all states |
| **UI states** | (If UI tests are in scope) Each of the 5 badge variants renders correctly |
| **Idempotency and overwrite** | Double approval: approving an already-approved KU does not create a duplicate commitment. Repeated commit: `POST /zkp/commit` on an already-committed KU overwrites cleanly and returns a new root. Re-commit after failure: calling `POST /zkp/commit` on a `"failed"` KU resets state to `"committed"` and logs `"overwrite": true`. Stale re-verification: repeated retrieval on a stale KU re-verifies only once per access, not redundantly. Overwrite audit: every overwrite emits an `INFO`-level log entry with the `unit_id`; tests assert this log line is present. |
| **Concurrent access** | Concurrent query + commit on the same KU does not corrupt state (SQLite WAL serializes writes); concurrent retrieval verification produces consistent results. **Note:** these guarantees are specific to the current SQLite storage backend. If the backend changes (e.g. to PostgreSQL), concurrency tests must be revisited for the new isolation model. |

### Validation Commands

```bash
# From repo root
make lint    # ruff check + ruff format --check
make test    # pytest for both team-api and plugin
```

---

## 19. PR Packaging Plan

The PR split below is meant to isolate review concerns, not to imply that code was developed in exactly this order. The working branch already contains all listed code with 349 passing tests; the split gives maintainers focused review scopes.

### PR 1: Design Doc + Provider Abstraction (Stories 0–2)

**What ships:**
- This design document (`docs/plans/2026-03-29-zkp-selective-disclosure-design.md`)
- `ZKPProvider` Protocol + `HashCommitmentProvider` in both `team-api/team_api/zkp.py` and `plugins/cq/server/cq_mcp/zkp.py`
- `get_provider()` / `set_provider()` module-level API
- `zkp_routes.py` with the 3 REST endpoints
- `server.py` MCP tool additions (`zkp_commit`, `zkp_disclose`, `zkp_verify`)
- All existing tests (27 team-api + 11 plugin ZKP-specific)
- Schema additions: `commitments` table, `commitment_root` column

**Review focus:** Is the `ZKPProvider` interface the right abstraction? Is hash-commitment acceptable as a Phase 1 PoC?

### PR 2: Lifecycle Integration + Rich State (Stories 3–6)

**What ships:**
- `review.py` changes: auto-commit on `approve_unit()`
- New KU model fields: `proof_provider`, `proof_verified_at`, `proof_verification_result`
- Schema additions for the new columns
- Retrieval-time verification with state machine (none → committed → verified / failed / stale)
- Staleness threshold configuration
- Integration tests for the full commit → verify → stale cycle

**Review focus:** Is the 5-state model correct? Is 24h staleness the right default? Is lenient failure on approve acceptable?

### PR 3: API + UI Surface (Stories 7–8)

**What ships:**
- Rich `proof_status` block in API responses (provider, verified_at, verification_result)
- All 5 UI badge variants in `ReviewCard.tsx`
- TypeScript type updates in `types.ts`
- `make lint` + `make test` green across all packages

**Review focus:** Are the UI states and colours right? Does the API response shape make sense for consumers?

### Commit History

The working branch has a natural commit history from development. Each PR can be squash-merged or rebased per maintainer preference.

---

## 20. Security Considerations

### Phase 1 Limitations

| Concern | Mitigation |
|---|---|
| **Not a true ZKP** | The hash-commitment scheme provides binding + hiding + selective disclosure but is not a zero-knowledge proof in the formal sense. The verifier sees undisclosed leaf hashes, which could theoretically leak information about field distribution. The `ZKPProvider` interface is designed so Midnight's true ZKP backend can replace this without changing call sites. |
| **Salt storage** | Salts are stored in the `commitments` table alongside the KU. In production (Phase 2+), salts would be managed by the prover and not persisted server-side. |
| **Commitment immutability** | Commitments are generated at graduation time. If a committed field is mutated after graduation, the commitment becomes invalid. Phase 1 detects this via retrieval verification (`verify_commitment_integrity()`). Phase 3 adds re-commitment on mutation. |
| **Timing attacks** | `secrets.compare_digest()` is used for root comparison to prevent timing-based side channels. |
| **No proof of deletion** | Phase 1 does not prove data was deleted. This is a Phase 2 goal — Midnight's on-chain proofs may enable this, depending on the final integration model. |

### OWASP Alignment

> **⚠️ Not for adversarial environments.** Phase 1 assumes a single trusted team domain. The hash-commitment scheme, server-side salt storage, and lack of per-user authorization make this design **unsuitable for multi-tenant, public-facing, or adversarial deployments** without the hardening described in Phase 2–3. If your deployment includes untrusted users, external API consumers, or multi-tenancy, do not ship Phase 1 without tightening the authorization model first.

- **Injection:** All SQL uses parameterised queries. No string interpolation.
- **Broken auth:** ZKP endpoints inherit existing JWT auth via `get_current_user` dependency.
- **Sensitive data exposure:** Salts are never included in API responses that go to consumers (only returned to the original committer on `/zkp/commit`).
- **Mass assignment:** All request/response models use Pydantic with explicit field definitions.

---

## 21. Open Questions for Maintainers

The most critical decisions are in the [Decisions Requested](#decisions-requested-from-maintainers) table at the top. The questions below are lower-priority items where I have a recommendation but would appreciate input:

1. **Midnight timeline.** I recommend building out the full Phase 1 infrastructure regardless of when Midnight SDK becomes available, because the `ZKPProvider` interface means all Phase 1 code carries forward — nothing is throwaway. If Midnight is imminent (weeks not months), let me know and I'll prioritise the `describe_capabilities()` extension point to smooth the transition.

2. **Global tier proof portability.** When a KU graduates from Team → Global, I recommend **not** carrying the team-tier proof forward. The global tier should generate its own commitment under its own trust domain. The team proof attests to team-level data integrity; the global proof should attest to global-level integrity. Phase 3 (Story 3.5) is the right place to implement this.

3. **Compliance dashboard priority.** Phase 4 proposes a compliance dashboard (proof coverage %, failure rates). I recommend deferring this entirely until Midnight integration is underway, since the dashboard would need redesign for on-chain proofs anyway. Unless there's near-term compliance reporting pressure?

4. **Per-domain proof configuration.** Phase 3 proposes per-domain or per-tier proof scheme selection. I recommend sticking with a single scheme globally in Phase 1–2 and only adding per-domain config if a concrete use case emerges. Premature configurability adds complexity without clear benefit.

5. **Proof expiration policy.** Should commitments expire after some absolute time (e.g. 90 days)? I recommend **no expiration** in Phase 1 — commitments are valid indefinitely, staleness only applies to *verification results*. If regulatory requirements mandate proof refresh, that's a Phase 3 concern.

---

## Appendix A: File Inventory

Files created or modified as part of this work:

| File | Change Type | Purpose |
|---|---|---|
| `docs/plans/2026-03-29-zkp-selective-disclosure-design.md` | New | This design document |
| `team-api/team_api/zkp.py` | New | ZKPProvider protocol, HashCommitmentProvider, crypto primitives |
| `team-api/team_api/zkp_routes.py` | New | REST endpoints for commit, disclose, verify |
| `team-api/team_api/tables.py` | Modified | Schema migration for commitment_root column + commitments table |
| `team-api/team_api/store.py` | Modified | store_commitment(), get_commitment(), has_commitment() |
| `team-api/team_api/knowledge_unit.py` | Modified | Added commitment_root field |
| `team-api/team_api/review.py` | Modified | Auto-commit on approve; proof_status in ReviewItem |
| `team-api/team_api/app.py` | Modified | Registered zkp_router |
| `team-api/tests/test_zkp.py` | New | 27 tests for ZKP core + API endpoints |
| `plugins/cq/server/cq_mcp/zkp.py` | New | Plugin-side ZKPProvider (mirrors team-api) |
| `plugins/cq/server/cq_mcp/server.py` | Modified | zkp_commit, zkp_disclose, zkp_verify tools |
| `plugins/cq/server/cq_mcp/local_store.py` | Modified | Commitment storage for local store |
| `plugins/cq/server/tests/test_zkp.py` | New | 11 tests for plugin ZKP + store |
| `team-ui/src/types.ts` | Modified | commitment_root on KU, proof_status on ReviewItem |
| `team-ui/src/components/ReviewCard.tsx` | Modified | Proof status badge |
| `team-ui/src/pages/ReviewPage.tsx` | Modified | Pass proofStatus to ReviewCard |

## Appendix B: Example API Payloads

> **⚠️ Phase 1 proof format: internal.** All payloads below are CQ-internal implementation examples. Field names, nesting, and serialization may change without notice between phases. Do not treat these shapes as a stable external contract. See [Section 10.2](#102-zkp-specific-endpoints-implemented) for the full format classification.
>
> **Stability rule:** Phase 1 disclosure proof payloads are not a long-term compatibility contract and may change before Phase 2 externalization. Any consumer that parses these payloads must be prepared for breaking changes.

### Commitment Creation

> **⚠️ Privileged response.** This payload includes salts and leaf hashes. It is returned **only** to the caller who creates the commitment (typically the server itself during graduation). It MUST NOT be exposed to consumers or included in query responses. The `/query` and `/review` endpoints never return salt material.

**Request:** `POST /zkp/commit/ku_a1b2c3d4`

**Response:**
```json
{
  "unit_id": "ku_a1b2c3d4",
  "root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "commitment": {
    "unit_id": "ku_a1b2c3d4",
    "root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "salts": {
      "context": "a1b2c3...",
      "created_by": "d4e5f6...",
      "domain": "g7h8i9...",
      "evidence.confidence": "j0k1l2...",
      "insight.action": "m3n4o5...",
      "insight.detail": "p6q7r8...",
      "insight.summary": "s9t0u1..."
    },
    "leaf_hashes": {
      "context": "2cf24dba5...",
      "created_by": "4e07408a...",
      "domain": "6b86b273f...",
      "evidence.confidence": "d4735e3a...",
      "insight.action": "4b22777...",
      "insight.detail": "ef2d127d...",
      "insight.summary": "e7f6c011..."
    }
  }
}
```

### Selective Disclosure

> **⚠️ Internal format.** This payload structure is a Phase 1 implementation detail and may change without notice. Do not treat it as a stable contract.

**Request:** `POST /zkp/disclose/ku_a1b2c3d4`
```json
{
  "fields": ["insight.summary", "domain"]
}
```

**Response:**
```json
{
  "unit_id": "ku_a1b2c3d4",
  "proof": {
    "unit_id": "ku_a1b2c3d4",
    "root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "disclosed": {
      "insight.summary": "Stripe returns 200 with error body for rate limits",
      "domain": "[\"api\",\"payments\"]"
    },
    "disclosed_salts": {
      "insight.summary": "s9t0u1...",
      "domain": "g7h8i9..."
    },
    "undisclosed_leaves": {
      "context": "2cf24dba5...",
      "created_by": "4e07408a...",
      "evidence.confidence": "d4735e3a...",
      "insight.action": "4b22777...",
      "insight.detail": "ef2d127d..."
    }
  }
}
```

### Verification

> **⚠️ Internal format.** Proof structure and response shape are Phase 1 implementation details and may change without notice.

**Request:** `POST /zkp/verify`
```json
{
  "proof": { "...same proof object as above..." }
}
```

**Response:**
```json
{
  "valid": true,
  "unit_id": "ku_a1b2c3d4"
}
```

### Review Queue Item (with proof status)

```json
{
  "knowledge_unit": {
    "id": "ku_a1b2c3d4",
    "commitment_root": "e3b0c44298fc1c...",
    "...": "..."
  },
  "status": "approved",
  "reviewed_by": "alice",
  "reviewed_at": "2026-03-29T10:00:00Z",
  "proof_status": "verified",
  "proof_provider": "hash-commitment",
  "proof_verified_at": "2026-03-29T10:05:00Z"
}
```

---

## Decision Summary: Proposed Defaults

After reading the full document, here is what I am asking maintainers to approve for Phase 1:

> **Approve Phase 1 as:** advisory proof state (no hard gates), trusted-team authorization (single trust domain, no per-user ownership), server-side salt storage (PoC simplification), no automatic backfill of historical KUs, single root-computation algorithm (hash-commitment only), three-PR rollout (design + provider, lifecycle + schema, API + UI). Lenient failure on graduation (approval succeeds even if commitment fails). Cached verification with 24-hour staleness threshold. Current 7-field committed set.

If any of these defaults are unacceptable, see the [Decisions Requested](#decisions-requested-from-maintainers) table for alternatives and trade-offs.
