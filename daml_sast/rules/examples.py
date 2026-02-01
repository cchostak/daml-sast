from __future__ import annotations

from typing import Optional

from daml_sast.analysis.lifecycle import collect_update_ops
from daml_sast.analysis.party import infer_party_set
from daml_sast.ir.model import Choice, Expr, Location, Template
from daml_sast.model import Confidence, Evidence, Finding, Severity
from daml_sast.rules.base import Ctx, Rule, RuleMeta


def _location_from(expr: Optional[Expr], ctx: Ctx, default_def: str) -> Location:
    if expr and expr.location:
        return expr.location
    return Location(module=ctx.module_name or "<unknown>", definition=default_def)


def _expr_is_direct_party_list_var(expr: Expr) -> bool:
    return expr.kind == "var" and expr.typ is not None and expr.typ.is_party_list()


def _expr_contains_get_time(expr: Expr) -> bool:
    for op in collect_update_ops(expr):
        if op.kind == "get_time":
            return True
    if expr.kind == "builtin" and expr.value == "getTime":
        return True
    for child in expr.children:
        if _expr_contains_get_time(child):
            return True
    return False


class AuthControllerAlignmentRule(Rule):
    meta = RuleMeta(
        id="DAML-AUTH-001",
        title="Controller not aligned with signatories",
        description="Choice controllers are not a subset of template signatories or key maintainers.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="auth",
        rationale="Controllers who are not signatories/maintainers can exercise choices without authorization.",
        tags=["authorization"],
    )

    def visit_choice(self, ctx: Ctx, template: Template, choice: Choice, emit) -> None:
        controllers = infer_party_set(choice.controllers)
        signatories = infer_party_set(template.signatories)
        maintainers = infer_party_set(template.key.maintainers) if template.key else None

        allowed = signatories
        if maintainers is not None:
            allowed = allowed.union(maintainers)

        if controllers.is_definitely_not_subset_of(allowed):
            loc = _location_from(choice.controllers, ctx, f"Choice {choice.name}")
            emit(
                Finding(
                    id=self.meta.id,
                    title=self.meta.title,
                    severity=self.meta.severity,
                    confidence=self.meta.confidence,
                    category=self.meta.category,
                    message="Choice controllers are not a subset of signatories/maintainers.",
                    location=loc,
                    evidence=[
                        Evidence(
                            kind="choice",
                            note="controllers expression",
                            lf_ref=choice.controllers.lf_ref,
                        )
                    ],
                    metadata={"template": template.name, "choice": choice.name},
                )
            )


class NonconsumingCreateRule(Rule):
    meta = RuleMeta(
        id="DAML-LIFE-001",
        title="Nonconsuming choice creates new contract",
        description="Nonconsuming choices that create new contracts can duplicate assets.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="lifecycle",
        rationale="Nonconsuming choices that create new contracts can inflate assets unintentionally.",
        tags=["lifecycle", "asset"],
    )

    def visit_choice(self, ctx: Ctx, template: Template, choice: Choice, emit) -> None:
        if choice.consuming:
            return
        ops = collect_update_ops(choice.update)
        if any(op.kind == "create" and op.template == template.name for op in ops):
            loc = _location_from(choice.update, ctx, f"Choice {choice.name}")
            emit(
                Finding(
                    id=self.meta.id,
                    title=self.meta.title,
                    severity=self.meta.severity,
                    confidence=self.meta.confidence,
                    category=self.meta.category,
                    message="Nonconsuming choice creates a new contract of the same template.",
                    location=loc,
                    evidence=[
                        Evidence(
                            kind="update",
                            note="update.create of same template",
                            lf_ref=choice.update.lf_ref,
                        )
                    ],
                    metadata={"template": template.name, "choice": choice.name},
                )
            )


class OverbroadObserversRule(Rule):
    meta = RuleMeta(
        id="DAML-PRIV-001",
        title="Over-broad observers",
        description="Observers derived directly from a party list variable may be too permissive.",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="privacy",
        rationale="Unfiltered party lists in observers can cause unintended divulgence.",
        tags=["privacy", "divulgence"],
    )

    def visit_template(self, ctx: Ctx, template: Template, emit) -> None:
        if _expr_is_direct_party_list_var(template.observers):
            loc = _location_from(template.observers, ctx, f"Template {template.name}")
            emit(
                Finding(
                    id=self.meta.id,
                    title=self.meta.title,
                    severity=self.meta.severity,
                    confidence=self.meta.confidence,
                    category=self.meta.category,
                    message="Template observers derived directly from a party list variable.",
                    location=loc,
                    evidence=[
                        Evidence(
                            kind="template",
                            note="observers expression",
                            lf_ref=template.observers.lf_ref,
                        )
                    ],
                    metadata={"template": template.name},
                )
            )

    def visit_choice(self, ctx: Ctx, template: Template, choice: Choice, emit) -> None:
        if choice.observers and _expr_is_direct_party_list_var(choice.observers):
            loc = _location_from(choice.observers, ctx, f"Choice {choice.name}")
            emit(
                Finding(
                    id=self.meta.id,
                    title=self.meta.title,
                    severity=self.meta.severity,
                    confidence=self.meta.confidence,
                    category=self.meta.category,
                    message="Choice observers derived directly from a party list variable.",
                    location=loc,
                    evidence=[
                        Evidence(
                            kind="choice",
                            note="observers expression",
                            lf_ref=choice.observers.lf_ref,
                        )
                    ],
                    metadata={"template": template.name, "choice": choice.name},
                )
            )


class KeyMaintainersAlignmentRule(Rule):
    meta = RuleMeta(
        id="DAML-KEY-001",
        title="Key maintainers not aligned with signatories",
        description="Key maintainers are not a subset of template signatories.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="key",
        rationale="Misaligned maintainers can enable unexpected key lookups or disclosure.",
        tags=["key", "authorization"],
    )

    def visit_template(self, ctx: Ctx, template: Template, emit) -> None:
        if not template.key:
            return
        maintainers = infer_party_set(template.key.maintainers)
        signatories = infer_party_set(template.signatories)
        if maintainers.is_definitely_not_subset_of(signatories):
            loc = _location_from(template.key.maintainers, ctx, f"Template {template.name}")
            emit(
                Finding(
                    id=self.meta.id,
                    title=self.meta.title,
                    severity=self.meta.severity,
                    confidence=self.meta.confidence,
                    category=self.meta.category,
                    message="Key maintainers are not a subset of signatories.",
                    location=loc,
                    evidence=[
                        Evidence(
                            kind="key",
                            note="maintainers expression",
                            lf_ref=template.key.maintainers.lf_ref,
                        )
                    ],
                    metadata={"template": template.name},
                )
            )


class DeterminismTimeRule(Rule):
    meta = RuleMeta(
        id="DAML-DET-001",
        title="Ledger time used in authorization/key logic",
        description="Ledger time is referenced in authorization or key logic.",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category="determinism",
        rationale="Time-dependent auth or keys can be brittle and replay-sensitive.",
        tags=["determinism"],
    )

    def _check(self, ctx: Ctx, owner: str, expr: Expr, emit) -> None:
        if not _expr_contains_get_time(expr):
            return
        loc = _location_from(expr, ctx, f"{owner} expression")
        emit(
            Finding(
                id=self.meta.id,
                title=self.meta.title,
                severity=self.meta.severity,
                confidence=self.meta.confidence,
                category=self.meta.category,
                message=f"Ledger time referenced in {owner} logic.",
                location=loc,
                evidence=[
                    Evidence(kind="expr", note=f"{owner} expression", lf_ref=expr.lf_ref)
                ],
                metadata={"owner": owner, "template": ctx.template_name or ""},
            )
        )

    def visit_template(self, ctx: Ctx, template: Template, emit) -> None:
        self._check(ctx, "template signatories", template.signatories, emit)
        self._check(ctx, "template observers", template.observers, emit)
        if template.key:
            self._check(ctx, "key body", template.key.body, emit)
            self._check(ctx, "key maintainers", template.key.maintainers, emit)

    def visit_choice(self, ctx: Ctx, template: Template, choice: Choice, emit) -> None:
        self._check(ctx, "choice controllers", choice.controllers, emit)
        if choice.observers:
            self._check(ctx, "choice observers", choice.observers, emit)
