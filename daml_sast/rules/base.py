# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional, Protocol

from daml_sast.ir.model import Choice, Expr, Module, Package, Template
from daml_sast.model import Confidence, Finding, Severity


class ExprOwner(str, Enum):
    TEMPLATE_SIGNATORIES = "template_signatories"
    TEMPLATE_OBSERVERS = "template_observers"
    TEMPLATE_KEY_BODY = "template_key_body"
    TEMPLATE_KEY_MAINTAINERS = "template_key_maintainers"
    TEMPLATE_PRECOND = "template_precond"
    CHOICE_CONTROLLERS = "choice_controllers"
    CHOICE_OBSERVERS = "choice_observers"
    CHOICE_AUTHORIZERS = "choice_authorizers"
    CHOICE_UPDATE = "choice_update"
    VALUE_BODY = "value_body"


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    rationale: str
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Ctx:
    package_id: str
    module_name: str
    template_name: Optional[str] = None
    choice_name: Optional[str] = None
    path: tuple[str, ...] = ()

    def derive(
        self,
        *,
        template_name: Optional[str] = None,
        choice_name: Optional[str] = None,
        path_append: Optional[str] = None,
    ) -> "Ctx":
        path = self.path
        if path_append:
            path = (*path, path_append)
        return Ctx(
            package_id=self.package_id,
            module_name=self.module_name,
            template_name=template_name if template_name is not None else self.template_name,
            choice_name=choice_name if choice_name is not None else self.choice_name,
            path=path,
        )


class Emitter(Protocol):
    def __call__(self, finding: Finding) -> None:
        ...


class Rule:
    meta: RuleMeta

    def visit_package(self, ctx: Ctx, pkg: Package, emit: Emitter) -> None:
        pass

    def visit_module(self, ctx: Ctx, module: Module, emit: Emitter) -> None:
        pass

    def visit_template(self, ctx: Ctx, template: Template, emit: Emitter) -> None:
        pass

    def visit_choice(self, ctx: Ctx, template: Template, choice: Choice, emit: Emitter) -> None:
        pass

    def visit_expr(self, ctx: Ctx, owner: ExprOwner, expr: Expr, emit: Emitter) -> None:
        pass


RuleList = Iterable[Rule]
