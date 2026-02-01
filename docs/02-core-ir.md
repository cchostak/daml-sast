# Core Analysis IR (Simplified Daml-LF View)

Facts:
- Input is Daml-LF (protobuf) from .dar/.dalf.
- Daml-LF contains modules, templates, choices, and expressions.

Assumptions:
- We expose a reduced IR that preserves semantics relevant to authorization, privacy, and lifecycle.
- We keep references back to original Daml-LF nodes for location and debugging.

## IR Overview (language-agnostic pseudocode)

```text
Program
  packages: List<Package>

Package
  package_id: String
  name: String
  version: String
  modules: List<Module>
  lf_ref: LfPackageRef

Module
  name: String
  templates: List<Template>
  values: List<ValueDef>
  lf_ref: LfModuleRef

Template
  name: String
  params: List<Var>
  signatories: Expr
  observers: Expr
  key: Optional<TemplateKey>
  choices: List<Choice>
  precond: Optional<Expr>
  lf_ref: LfTemplateRef

TemplateKey
  typ: Type
  body: Expr
  maintainers: Expr
  lf_ref: LfTemplateKeyRef

Choice
  name: String
  consuming: Bool
  controllers: Expr
  observers: Optional<Expr>
  return_type: Type
  update: Expr
  lf_ref: LfChoiceRef

ValueDef
  name: String
  typ: Type
  body: Expr
  lf_ref: LfValueRef

Type (subset)
  - TCon(name)
  - TVar(name)
  - TApp(type, type)
  - TFun(param, result)
  - TTuple(fields)
  - TList(type)
  - TOptional(type)

Expr (subset, normalized)
  - EVar(name)
  - EValRef(pkg_id, module, name)
  - ELit(value)
  - EApp(fn, arg)
  - ELam(param, body)
  - ELet(bindings, body)
  - ECase(scrutinee, alts)
  - EUpdate(update_expr)
  - ERecord(fields)
  - EProject(record, field)
  - EStruct(fields)
  - EVariant(ctor, value)
  - EEnum(ctor)
  - EList(items)
  - EOptional(value?)
  - ETypeAbs(type_var, body)
  - ETypeApp(expr, type)
  - EBuiltin(name)
  - ELocation(loc, expr)  // preserves source spans if present

UpdateExpr (subset)
  - UCreate(template_type, record_expr)
  - UExercise(template_type, choice_name, cid_expr, arg_expr)
  - UFetch(template_type, cid_expr)
  - UArchive(template_type, cid_expr)
  - ULookupByKey(template_type, key_expr)
  - UFetchByKey(template_type, key_expr)
  - UGetTime
  - UPure(expr)
  - UBind(var, update_expr, body)
  - ULet(bindings, update_expr)

Location
  module: String
  definition: String
  span: Optional<SourceSpan>

SourceSpan
  file: Optional<String>
  start_line: Optional<Int>
  start_col: Optional<Int>
  end_line: Optional<Int>
  end_col: Optional<Int>
```

Notes:
- `Expr` nodes are shallow wrappers around Daml-LF expressions to keep traversal deterministic.
- `ELocation` is preserved when the Daml-LF includes location info; otherwise `span` is absent.
- `UpdateExpr` is separated to highlight contract lifecycle operations for rules.
- We do not invent additional semantic fields; derived data is computed in the walker/engine.
