# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from daml_sast.ir.model import Expr


@dataclass(frozen=True)
class UpdateOp:
    kind: str
    template: str | None = None
    choice: str | None = None


def collect_update_ops(expr: Expr) -> list[UpdateOp]:
    ops: list[UpdateOp] = []

    def walk(node: Expr) -> None:
        if node.kind.startswith("update."):
            if node.kind == "update.create":
                ops.append(UpdateOp(kind="create", template=_template_from(node)))
            elif node.kind == "update.create_interface":
                ops.append(UpdateOp(kind="create_interface", template=_template_from(node)))
            elif node.kind == "update.exercise":
                template, choice = _template_choice_from(node)
                ops.append(UpdateOp(kind="exercise", template=template, choice=choice))
            elif node.kind == "update.exercise_by_key":
                template, choice = _template_choice_from(node)
                ops.append(UpdateOp(kind="exercise_by_key", template=template, choice=choice))
            elif node.kind == "update.exercise_interface":
                template, choice = _template_choice_from(node)
                ops.append(UpdateOp(kind="exercise_interface", template=template, choice=choice))
            elif node.kind == "update.dynamic_exercise":
                template, choice = _template_choice_from(node)
                ops.append(UpdateOp(kind="dynamic_exercise", template=template, choice=choice))
            elif node.kind == "update.fetch":
                ops.append(UpdateOp(kind="fetch", template=_template_from(node)))
            elif node.kind == "update.soft_fetch":
                ops.append(UpdateOp(kind="soft_fetch", template=_template_from(node)))
            elif node.kind == "update.fetch_interface":
                ops.append(UpdateOp(kind="fetch_interface", template=_template_from(node)))
            elif node.kind == "update.soft_exercise":
                template, choice = _template_choice_from(node)
                ops.append(UpdateOp(kind="soft_exercise", template=template, choice=choice))
            elif node.kind == "update.lookup_by_key":
                ops.append(UpdateOp(kind="lookup_by_key", template=_template_from(node)))
            elif node.kind == "update.fetch_by_key":
                ops.append(UpdateOp(kind="fetch_by_key", template=_template_from(node)))
            elif node.kind == "update.ledger_time_lt":
                ops.append(UpdateOp(kind="ledger_time_lt"))
            elif node.kind == "update.get_time":
                ops.append(UpdateOp(kind="get_time"))

        for child in node.children:
            walk(child)

    walk(expr)
    return ops


def _template_from(node: Expr) -> str | None:
    if isinstance(node.value, str):
        return node.value
    return None


def _template_choice_from(node: Expr) -> tuple[str | None, str | None]:
    if isinstance(node.value, dict):
        return node.value.get("template"), node.value.get("choice")
    return None, None
