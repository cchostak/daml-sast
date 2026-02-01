# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field

from daml_sast.ir.model import Expr


@dataclass(frozen=True)
class PartySet:
    known: set[str] = field(default_factory=set)
    unknown: bool = False

    @classmethod
    def unknown_set(cls) -> "PartySet":
        return cls(set(), True)

    def union(self, other: "PartySet") -> "PartySet":
        return PartySet(known=self.known | other.known, unknown=self.unknown or other.unknown)

    def is_definitely_subset_of(self, other: "PartySet") -> bool:
        if self.unknown or other.unknown:
            return False
        return self.known.issubset(other.known)

    def is_definitely_not_subset_of(self, other: "PartySet") -> bool:
        if self.unknown or other.unknown:
            return False
        return not self.known.issubset(other.known)


def infer_party_set(expr: Expr, env: dict[str, PartySet] | None = None) -> PartySet:
    if env is None:
        env = {}

    if expr.kind == "party" and isinstance(expr.value, str):
        return PartySet(known={expr.value})

    if expr.kind == "list":
        acc = PartySet()
        for child in expr.children:
            acc = acc.union(infer_party_set(child, env))
            if acc.unknown:
                return acc
        return acc

    if expr.kind == "cons":
        if not expr.children:
            return PartySet.unknown_set()
        *head, tail = expr.children
        acc = PartySet()
        for child in head:
            acc = acc.union(infer_party_set(child, env))
        acc = acc.union(infer_party_set(tail, env))
        return acc

    if expr.kind == "var" and isinstance(expr.value, str):
        return env.get(expr.value, PartySet.unknown_set())

    if expr.kind == "let":
        local_env = dict(env)
        if not expr.children:
            return PartySet.unknown_set()
        *bindings, body = expr.children
        for binding in bindings:
            if binding.kind != "binding" or not binding.children:
                continue
            name = binding.value
            if not isinstance(name, str):
                continue
            bound_expr = binding.children[0]
            local_env[name] = infer_party_set(bound_expr, local_env)
        return infer_party_set(body, local_env)

    if expr.kind == "case":
        if len(expr.children) < 2:
            return PartySet.unknown_set()
        acc = PartySet()
        for alt in expr.children[1:]:
            acc = acc.union(infer_party_set(alt, env))
            if acc.unknown:
                return acc
        return acc

    return PartySet.unknown_set()
