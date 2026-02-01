# Rule Catalog

This catalog documents the current MVP rules. It focuses on what the rule checks, why it matters, example triggers, and expected false positives.

## DAML-AUTH-001 — Controller Not Aligned With Signatories

- Category: auth
- Severity: MEDIUM
- Confidence: MEDIUM

What it checks:
- Choice controllers are not a subset of template signatories or key maintainers.
- Uses party-set inference (literal parties, simple `let` bindings, list construction).

Rationale:
- Controllers who are not signatories/maintainers can exercise choices without the expected authorization boundary.

Example trigger (pseudo):
```text
template TAuth
  signatory [Alice]
  choice Transfer controller [Bob] = ...
```

Expected false positives:
- Deliberate delegation patterns (e.g., a designated operator acts on behalf of signatories).
- Controllers inferred from simple logic not captured by the current inference (will be "unknown" and not flagged).

---

## DAML-LIFE-001 — Nonconsuming Choice Creates New Contract

- Category: lifecycle
- Severity: HIGH
- Confidence: MEDIUM

What it checks:
- Nonconsuming choice whose update contains `create` of the same template.
- Uses update-op extraction from LF update nodes.

Rationale:
- Nonconsuming choices that create new contracts can accidentally mint/duplicate assets.

Example trigger (pseudo):
```text
choice Mint (nonconsuming) = do
  create this
```

Expected false positives:
- Intentional mint/burn patterns that deliberately duplicate or roll forward assets.

---

## DAML-PRIV-001 — Over-broad Observers

- Category: privacy
- Severity: MEDIUM
- Confidence: LOW

What it checks:
- Observers derived directly from an unfiltered `List Party` variable.

Rationale:
- Over-broad observers can cause unintended divulgence.

Example trigger (pseudo):
```text
observers = parties  -- parties : List Party
```

Expected false positives:
- Legitimate broadcast-style contracts (e.g., public announcements).
- Observers list already pre-filtered in prior logic (not visible to the analyzer).

---

## DAML-KEY-001 — Key Maintainers Not Aligned With Signatories

- Category: key
- Severity: MEDIUM
- Confidence: MEDIUM

What it checks:
- Key maintainers are not a subset of signatories.

Rationale:
- Misaligned maintainers can enable unexpected key lookups or disclosure.

Example trigger (pseudo):
```text
key (k) maintainer [Bob]
signatory [Alice]
```

Expected false positives:
- Cases where maintainers are intentionally a broader operational group.

---

## DAML-DET-001 — Ledger Time Used in Authorization/Key Logic

- Category: determinism
- Severity: LOW
- Confidence: LOW

What it checks:
- Ledger time references in signatories, observers, controllers, or key logic.
- Uses update-op extraction (`get_time`) and builtin checks.

Rationale:
- Time-dependent authorization or key logic can be brittle and replay-sensitive.

Example trigger (pseudo):
```text
signatory if getTime < deadline then [Alice] else []
```

Expected false positives:
- Legitimate time-window authorization patterns.
- References to ledger time in non-auth logic that happen to flow into these expressions.
