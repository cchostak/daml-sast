# Example Rules (MVP)

Assumptions:
- Rules operate on the simplified IR and use pattern matching on expressions.
- Heuristics are acceptable when true semantic checks are unavailable.

## DAML-AUTH-001: Controller Not Aligned With Signatories

Rationale:
- Controllers who are not signatories can exercise choices on contracts they do not authorize.
- This is sometimes intentional (e.g., delegated authority), so use MEDIUM confidence.

Heuristic:
- If `choice.controllers` expression is not syntactically a subset of `template.signatories` (or key maintainers when a key exists), emit.

Pseudocode:
```text
if !controllers_subset_of(signatories_or_maintainers):
  emit("Choice controllers are not aligned with signatories/maintainers")
```

## DAML-LIFE-001: Nonconsuming Choice With Asset-like Effect

Rationale:
- A nonconsuming choice that creates new contracts can duplicate assets.
- This is a common source of unintended inflation or double-spend logic.

Heuristic:
- If `choice.consuming == false` and `choice.update` contains `UCreate` of the same template (or an obvious asset template), emit.

Pseudocode:
```text
if !choice.consuming and update_contains_create_of(template_name):
  emit("Nonconsuming choice creates new contracts")
```

## DAML-PRIV-001: Over-broad Observers

Rationale:
- Observers control divulgence. Over-broad observers can leak confidential data.

Heuristic:
- If `template.observers` or `choice.observers` directly uses a `List Party` field or choice argument without filtering (e.g., `observers = parties`), emit.

Pseudocode:
```text
if observers_expr_is_direct_party_list_ref():
  emit("Observers derived from unfiltered party list")
```

## DAML-KEY-001: Key Maintainers Not Aligned With Signatories

Rationale:
- Key maintainers can authorize lookups by key. Misalignment can disclose keys or allow unexpected fetches.

Heuristic:
- If `template.key.maintainers` is not a subset of `template.signatories`, emit.

Pseudocode:
```text
if key.exists and !maintainers_subset_of(signatories):
  emit("Key maintainers are not aligned with signatories")
```

## DAML-DET-001: Ledger Time Used in Authorization/Key Logic

Rationale:
- Time-dependent authorization or keys can be brittle and lead to replay hazards.

Heuristic:
- If `getTime` (or equivalent LF update) is referenced in:
  - signatories
  - observers
  - controllers
  - key body/maintainers
  emit with LOW confidence.

Pseudocode:
```text
if expr_uses_get_time(signatories | observers | controllers | key):
  emit("Ledger time used in authorization/key logic")
```

Notes:
- Each rule should include evidence pointing to the relevant expression node and choice/template.
- Use LOW confidence when heuristics cannot prove an actual violation.
