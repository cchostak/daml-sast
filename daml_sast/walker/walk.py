# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Iterable

from daml_sast.ir.model import Expr, Program
from daml_sast.rules.base import Ctx, ExprOwner, Rule


def _walk_expr(expr: Expr, ctx: Ctx, owner: ExprOwner, rules: Iterable[Rule], emit) -> None:
    for rule in rules:
        rule.visit_expr(ctx, owner, expr, emit)
    for child in expr.children:
        _walk_expr(child, ctx, owner, rules, emit)


def walk_program(program: Program, rules: Iterable[Rule], emit) -> None:
    for pkg in program.packages:
        pkg_ctx = Ctx(package_id=pkg.package_id, module_name="")
        for rule in rules:
            rule.visit_package(pkg_ctx, pkg, emit)
        for mod in pkg.modules:
            mod_ctx = Ctx(package_id=pkg.package_id, module_name=mod.name)
            for rule in rules:
                rule.visit_module(mod_ctx, mod, emit)
            for template in mod.templates:
                t_ctx = mod_ctx.derive(template_name=template.name, path_append=f"template:{template.name}")
                for rule in rules:
                    rule.visit_template(t_ctx, template, emit)
                _walk_expr(template.signatories, t_ctx, ExprOwner.TEMPLATE_SIGNATORIES, rules, emit)
                _walk_expr(template.observers, t_ctx, ExprOwner.TEMPLATE_OBSERVERS, rules, emit)
                if template.precond:
                    _walk_expr(template.precond, t_ctx, ExprOwner.TEMPLATE_PRECOND, rules, emit)
                if template.key:
                    _walk_expr(template.key.body, t_ctx, ExprOwner.TEMPLATE_KEY_BODY, rules, emit)
                    _walk_expr(template.key.maintainers, t_ctx, ExprOwner.TEMPLATE_KEY_MAINTAINERS, rules, emit)
                for choice in template.choices:
                    c_ctx = t_ctx.derive(choice_name=choice.name, path_append=f"choice:{choice.name}")
                    for rule in rules:
                        rule.visit_choice(c_ctx, template, choice, emit)
                    _walk_expr(choice.controllers, c_ctx, ExprOwner.CHOICE_CONTROLLERS, rules, emit)
                    if choice.observers:
                        _walk_expr(choice.observers, c_ctx, ExprOwner.CHOICE_OBSERVERS, rules, emit)
                    if choice.authorizers:
                        _walk_expr(choice.authorizers, c_ctx, ExprOwner.CHOICE_AUTHORIZERS, rules, emit)
                    _walk_expr(choice.update, c_ctx, ExprOwner.CHOICE_UPDATE, rules, emit)
            for value in mod.values:
                v_ctx = mod_ctx.derive(path_append=f"value:{value.name}")
                _walk_expr(value.body, v_ctx, ExprOwner.VALUE_BODY, rules, emit)
