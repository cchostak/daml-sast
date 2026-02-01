# Rule Interface (Bandit-style)

Assumptions:
- Rules operate on the simplified IR, not raw Daml source.
- Rules are deterministic and avoid global state beyond read-only context.

## Rule Metadata

```text
RuleMeta
  id: String              // e.g. DAML-AUTH-001
  title: String
  description: String
  severity: Severity      // LOW | MEDIUM | HIGH | CRITICAL
  confidence: Confidence  // LOW | MEDIUM | HIGH
  category: String        // auth | privacy | lifecycle | determinism | key
  tags: List<String>
  rationale: String
  references: List<String>  // URLs or doc refs (optional)
```

## Rule Interface

```text
Rule
  meta: RuleMeta
  // Called with a read-only context and a sink to emit findings.
  visit_package(ctx: Ctx, pkg: Package, emit: Emit)
  visit_module(ctx: Ctx, m: Module, emit: Emit)
  visit_template(ctx: Ctx, t: Template, emit: Emit)
  visit_choice(ctx: Ctx, t: Template, c: Choice, emit: Emit)
  visit_expr(ctx: Ctx, owner: ExprOwner, e: Expr, emit: Emit)
  // All methods are optional; default is no-op.
```

Notes:
- `ExprOwner` indicates where an expression appears (template signatories, choice controllers, update body, key maintainers, etc.).
- Rules should be side-effect free and only emit findings.

## Context and Emission

```text
Ctx
  package_id: String
  module_name: String
  template_name: Optional<String>
  choice_name: Optional<String>
  path: List<String>            // breadcrumb of IR path
  type_env: TypeEnv             // resolved type info if available

Emit
  function emit(finding: Finding)
```

## Finding (Rule Output)

```text
Finding
  id: String                    // rule id
  title: String
  severity: Severity
  confidence: Confidence
  message: String               // short, actionable
  category: String
  location: Location            // from IR
  evidence: List<Evidence>      // optional snippets or node refs
  related: List<Location>       // secondary locations (optional)
  metadata: Map<String, String> // rule-specific key/values
```

```text
Evidence
  kind: String        // e.g. "expr", "choice", "key"
  note: String        // short explanation
  lf_ref: Optional<String>  // opaque reference to original Daml-LF node
```

Rule authorship guidelines:
- Avoid heavy inference; prefer direct checks on controllers, signatories, observers, keys, and update actions.
- Keep heuristics explicit and document in `rationale`.
- When uncertain, use lower confidence rather than suppressing output.
