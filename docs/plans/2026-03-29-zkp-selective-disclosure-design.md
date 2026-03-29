# Phase-1 Selective Disclosure Infrastructure for GDPR-Oriented Workflows

**Issue:** [#140 — Design and implement zero knowledge proof for GDPR compliance](https://github.com/mozilla-ai/cq/issues/140)
**Author:** (contributor name)
**Date:** 2026-03-29
**Status:** Draft — awaiting maintainer review

> **Note on scope:** Phase 1 implements a hash-commitment selective disclosure scheme — not a true zero-knowledge proof. It provides binding, hiding, and selective disclosure using standard-library SHA-256 behind a `ZKPProvider` interface designed for drop-in replacement by Midnight's ZKP infrastructure in Phase 2. This document uses "ZKP" as the project-level label for the privacy layer, matching the architecture doc and issue #140, while being precise about what Phase 1 actually delivers.

---

## My Understanding of Scope

I understand this feature is about proving compliance—ensuring, for instance, that data usage follows privacy rules—without exposing sensitive information. The system would generate these proofs during data use or model training so we can show compliance. If I'm misunderstanding, please let me know so we can adjust the document accordingly before going further.

---

## Decisions Requested from Maintainers

Before continuing implementation beyond the existing prototype, I need maintainer sign-off on these six decisions. Each includes my recommended default and the alternative. If no objection is raised, I will proceed with the recommended option.

| # | Decision | Recommendation | Alternative | Why |
|---|---|---|---|---|
| **D1** | Proof generation failure during `approve_unit()` | **Lenient:** approval succeeds, proof is missing, warning logged | Strict: roll back approval on commitment failure | Blocking approval for a PoC privacy feature risks disrupting the core review workflow. Lenient lets us ship safely; strict can be revisited when Midnight is integrated and proofs are mandatory. |
| **D2** | Retrieval-time verification strategy | **Cached with 24-hour staleness:** verify once, cache result, re-verify when stale | Verify on every read | Per-read verification adds ~1ms per KU to every query. Cached verification with a configurable threshold is fast, still catches tampering within 24h, and avoids unnecessary overhead for the PoC. |
| **D3** | Salt ownership model (Phase 1) | **Server-side storage:** salts persisted in `commitments` table alongside KU | Client-held salts: return to committer only, do not persist | Server-side is simpler for PoC: the team API can generate disclosure proofs for any committed KU without requiring the original committer. Downside: the server is a single trust domain. Phase 2 Midnight integration removes this concern since proofs are generated on-chain. |
| **D4** | PR packaging | **Three PRs:** (1) design doc + provider abstraction, (2) lifecycle + schema, (3) API/UI surface | Single PR with everything | Three PRs align with the contributing guide's preference for well-scoped changes. Each PR is independently reviewable and mergeable. |
| **D5** | KU mutation after commitment | **Detect-and-flag:** mutations (confirm, flag) cause retrieval verification to return `"failed"`, surfaced to consumers; no auto-regeneration in Phase 1 | Auto-regenerate commitment on every mutation | Detect-and-flag is simpler, makes mutation visible rather than silently patching it, and avoids re-commitment overhead. Auto-regeneration is Phase 3. |
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

### State Transitions

```
[no commitment]
        │
        │ approve_unit() → create_commitment()
        ▼
    committed
        │
        │ retrieval triggers verify_disclosure_proof()
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
| **Phase 1 NEW** `store.py → get()` | Will call `verify_disclosure_proof()` on retrieval |

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

### 9.2 Retrieval Verification (Proposed — Phase 1)

**Trigger:** `GET /query?domain=...` and `GET /review/{unit_id}`

**Behaviour:**
1. After fetching a KU, check whether a commitment exists.
2. If yes, reconstruct the commitment's root from the current KU field values and compare against the stored `commitment_root`.
3. Record the verification result and timestamp.

**Proof Status State Machine:**

The proof-state machine is defined in [Section 2: Canonical Proof-State Model](#2-canonical-proof-state-model). The state transitions and derivation rules are the single source of truth for all code.

**Staleness rule:** A verification result older than a configurable threshold (default: 24 hours) is marked `"stale"` and re-verified on next access. This avoids re-verifying on every single query while catching data corruption or tampering.

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

| Endpoint | Method | Purpose |
|---|---|---|
| `/zkp/commit/{unit_id}` | POST | Create a commitment for a KU. Returns the full commitment including salts (caller holds privately). |
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
- If the KU was mutated after commitment, `proof_status` will be `"failed"`.
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

### Backfill Strategy

**Phase 1: No backfill.** Only newly-approved KUs get commitments. Existing KUs remain in `"none"` state indefinitely unless a reviewer explicitly calls `POST /zkp/commit/{unit_id}` via the API.

**Rationale:** Backfilling would generate commitments from current data, not data-at-graduation-time. These commitments would be valid but misleading — they prove the KU hasn't changed *since backfill*, not *since graduation*. Phase 3 can add an explicit backfill command with clear semantics (e.g. "re-committed at [timestamp], original graduation commitment not available").

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
| Commitment generated | `"ZKP commitment created"` | `unit_id`, `provider` |
| Commitment generation failed | `"ZKP commitment failed"` (WARNING) | `unit_id`, `error` |
| Disclosure proof generated | `"ZKP disclosure proof created"` | `unit_id`, `disclosed_fields` |
| Verification performed | `"ZKP verification result"` | `unit_id`, `valid` (bool) |

### Phase 3 Enhancements

- Add `committed_by` column to `commitments` table.
- Restrict re-commitment to the original committer or an admin.
- Emit structured audit events (not just log lines) for compliance reporting.
- Record all proof operations in a dedicated `proof_audit_log` table.

---

## 16. Performance and Observability

### Expected Overhead

| Operation | Time (measured on prototype) | Acceptable Threshold |
|---|---|---|
| `create_commitment()` | < 1 ms (7 SHA-256 hashes + 1 root hash) | 5 ms |
| `create_disclosure_proof()` | < 1 ms (subset of hashes + assembly) | 5 ms |
| `verify_disclosure_proof()` | < 1 ms (recompute + compare) | 5 ms |
| Retrieval with cached verification | 0 ms (read from DB) | 0 ms |
| Retrieval with live verification | < 1 ms (1 verify) | 10 ms per KU |

SHA-256 is CPU-bound but extremely fast for 7 small fields. Even at 1000 KUs, a full verification sweep takes < 1 second.

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
| `zkp_verification_duration_seconds` | Histogram | Time spent in `verify_disclosure_proof()` |
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

### Validation Commands

```bash
# From repo root
make lint    # ruff check + ruff format --check
make test    # pytest for both team-api and plugin
```

---

## 19. PR Packaging Plan

> **Branch reality:** All the code listed in Appendix A already exists on the working branch with 349 passing tests. The question is not "what to write" but "how to split the existing code into reviewable PRs."

### PR 1: Design Doc + Provider Abstraction (Stories 0–2)

**What ships:**
- This design document (`docs/plans/2026-03-29-zkp-selective-disclosure-design.md`)
- `ZKPProvider` Protocol + `HashCommitmentProvider` in both `team-api/team_api/zkp.py` and `plugins/cq/server/cq_mcp/zkp.py`
- `get_provider()` / `set_provider()` module-level API
- `zkp_routes.py` with the 3 REST endpoints
- `server.py` MCP tool additions (`zkp_commit`, `zkp_disclose`, `zkp_verify`)
- All existing tests (27 team-api + 11 plugin ZKP-specific)
- Schema additions: `commitments` table, `commitment_root` column

**How to extract:** Cherry-pick or `git diff` the relevant files from the working branch. No code changes needed — these files are already in final form.

**Review focus:** Is the `ZKPProvider` interface the right abstraction? Is hash-commitment acceptable as a Phase 1 PoC?

### PR 2: Lifecycle Integration + Rich State (Stories 3–6)

**What ships:**
- `review.py` changes: auto-commit on `approve_unit()`
- New KU model fields: `proof_provider`, `proof_verified_at`, `proof_verification_result`
- Schema additions for the new columns
- Retrieval-time verification with state machine (none → committed → verified / failed / stale)
- Staleness threshold configuration
- Integration tests for the full commit → verify → stale cycle

**How to extract:** The graduation hook in `review.py` already exists. The new model fields and retrieval verification are the remaining implementation work in Phase 1. This PR is partly done (graduation hook, basic proof_status) and partly new (rich states, cached verification).

**Review focus:** Is the 5-state model correct? Is 24h staleness the right default? Is lenient failure on approve acceptable?

### PR 3: API + UI Surface (Stories 7–8)

**What ships:**
- Rich `proof_status` block in API responses (provider, verified_at, verification_result)
- All 5 UI badge variants in `ReviewCard.tsx`
- TypeScript type updates in `types.ts`
- `make lint` + `make test` green across all packages

**How to extract:** TypeScript changes and UI badge are partially done (2 of 5 states). Extend existing code rather than rewriting.

**Review focus:** Are the UI states and colours right? Does the API response shape make sense for consumers?

### Commit History

The working branch has a natural commit history from development. If maintainers prefer squashed PRs, each PR can be squash-merged. If they prefer a clean commit-per-story history, I can rebase interactively before opening the PRs.

---

## 20. Security Considerations

### Phase 1 Limitations

| Concern | Mitigation |
|---|---|
| **Not a true ZKP** | The hash-commitment scheme provides binding + hiding + selective disclosure but is not a zero-knowledge proof in the formal sense. The verifier sees undisclosed leaf hashes, which could theoretically leak information about field distribution. The `ZKPProvider` interface is designed so Midnight's true ZKP backend can replace this without changing call sites. |
| **Salt storage** | Salts are stored in the `commitments` table alongside the KU. In production (Phase 2+), salts would be managed by the prover and not persisted server-side. |
| **Commitment immutability** | Commitments are generated at graduation time. If a KU is mutated after commitment (e.g. by confirmation or flagging), the commitment becomes stale. Phase 1 detects this via retrieval verification. Phase 3 adds re-commitment on mutation. |
| **Timing attacks** | `secrets.compare_digest()` is used for root comparison to prevent timing-based side channels. |
| **No proof of deletion** | Phase 1 does not prove data was deleted. This is a Phase 2 goal—Midnight's on-chain proofs can provide this. |

### OWASP Alignment

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

### Commitment Creation

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
2026-03-29-zkp-selective-disclosure-design
