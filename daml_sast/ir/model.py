# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class SourceSpan:
    file: Optional[str] = None
    start_line: Optional[int] = None
    start_col: Optional[int] = None
    end_line: Optional[int] = None
    end_col: Optional[int] = None


@dataclass(frozen=True)
class Location:
    module: str
    definition: str
    span: Optional[SourceSpan] = None


@dataclass(frozen=True)
class Type:
    kind: str
    name: Optional[str] = None
    args: list["Type"] = field(default_factory=list)

    def is_party(self) -> bool:
        return self.kind == "con" and self.name == "Party"

    def is_party_list(self) -> bool:
        return self.kind == "list" and len(self.args) == 1 and self.args[0].is_party()


@dataclass
class Expr:
    kind: str
    value: Optional[Any] = None
    children: list["Expr"] = field(default_factory=list)
    location: Optional[Location] = None
    typ: Optional[Type] = None
    lf_ref: Optional[str] = None


@dataclass
class TemplateKey:
    typ: Type
    body: Expr
    maintainers: Expr
    location: Optional[Location] = None
    lf_ref: Optional[str] = None


@dataclass
class Choice:
    name: str
    consuming: bool
    controllers: Expr
    observers: Optional[Expr]
    authorizers: Optional[Expr]
    return_type: Optional[Type]
    update: Expr
    location: Optional[Location] = None
    lf_ref: Optional[str] = None


@dataclass
class Template:
    name: str
    params: list[str]
    signatories: Expr
    observers: Expr
    key: Optional[TemplateKey]
    choices: list[Choice]
    precond: Optional[Expr] = None
    location: Optional[Location] = None
    lf_ref: Optional[str] = None


@dataclass
class ValueDef:
    name: str
    typ: Optional[Type]
    body: Expr
    location: Optional[Location] = None
    lf_ref: Optional[str] = None


@dataclass
class Module:
    name: str
    templates: list[Template]
    values: list[ValueDef]
    location: Optional[Location] = None
    lf_ref: Optional[str] = None


@dataclass
class Package:
    package_id: str
    name: str
    version: str
    modules: list[Module]
    lf_ref: Optional[str] = None


@dataclass
class Program:
    packages: list[Package]
