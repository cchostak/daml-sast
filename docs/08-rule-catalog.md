# Rule Catalog

This catalog documents the current rules: what they check, why they matter, sample triggers, and false-positive guidance.

## DAML-AUTH-001 - Controller not aligned with signatories
- Category: auth | Severity: MEDIUM | Confidence: MEDIUM
- Checks: controllers not subset of signatories/maintainers.
- Trigger: `choice Transfer controller [Bob]` on a template signed by `[Alice]`.
- Guidance: If delegation is intentional, document it; otherwise align controllers or suppress.

## DAML-AUTH-002 - Controllers from uncontrolled data
- Category: auth | Severity: MEDIUM | Confidence: LOW
- Checks: controllers expression cannot be tied to known parties (unknown party set).
- Trigger: controllers derived from a choice argument or unknown variable.
- Guidance: Validate/whitelist controllers; suppress if forwarding is intentional.

## DAML-AUTH-003 - Template has no signatories
- Category: auth | Severity: HIGH | Confidence: MEDIUM
- Checks: signatories expression resolves to an empty set.
- Trigger: `signatory []`.
- Guidance: Add signatories or justify openness; otherwise suppress intentionally.

## DAML-AUTH-004 - Nonconsuming forwarding via exercise
- Category: auth | Severity: MEDIUM | Confidence: LOW
- Checks: nonconsuming choice that only exercises another choice (forwarding) without guards.
- Trigger: nonconsuming choice that calls `exercise`/`exercise_by_key` etc. directly.
- Guidance: Add guards/authorization checks; suppress if deliberate proxying.

## DAML-LIFE-001 - Nonconsuming choice creates same template
- Category: lifecycle | Severity: HIGH | Confidence: MEDIUM
- Checks: nonconsuming choice `create` of its own template.
- Trigger: `create this` inside nonconsuming choice.
- Guidance: Document intended minting; otherwise make choice consuming or remove create.

## DAML-LIFE-002 - Nonconsuming choice creates any contract
- Category: lifecycle | Severity: MEDIUM | Confidence: MEDIUM
- Checks: nonconsuming choice creates another template (not just self).
- Trigger: nonconsuming choice that `create` another template.
- Guidance: Ensure lifecycle is intended; otherwise make consuming or gate creation.

## DAML-PRIV-001 - Over-broad observers
- Category: privacy | Severity: MEDIUM | Confidence: LOW
- Checks: observers taken directly from a party-list variable.
- Trigger: `observers = parties` where `parties : List Party`.
- Guidance: Filter observers or justify broadcast; suppress if intentional.

## DAML-KEY-001 - Key maintainers not aligned with signatories
- Category: key | Severity: MEDIUM | Confidence: MEDIUM
- Checks: key maintainers not subset of signatories.
- Trigger: `key (...) maintainer [Bob]; signatory [Alice]`.
- Guidance: Align maintainers or document the policy; suppress if intentional.

## DAML-DET-001 - Ledger time in auth/key logic
- Category: determinism | Severity: LOW | Confidence: LOW
- Checks: `getTime` in signatories/observers/controllers/key logic.
- Trigger: `signatory if getTime < deadline then [Alice] else []`.
- Guidance: Confirm time window is intended; otherwise refactor or suppress.
