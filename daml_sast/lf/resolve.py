# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from daml_sast.lf.decoder import InternedTables


@dataclass(frozen=True)
class ResolvedName:
    package_id: str
    module: str
    name: str

    def fqn(self) -> str:
        return f"{self.module}.{self.name}" if self.module else self.name


class LfResolverBase:
    def __init__(self, package_id: str, interned: InternedTables) -> None:
        self.package_id = package_id
        self.interned = interned

    def interned_str(self, idx: int) -> str:
        if 0 <= idx < len(self.interned.strings):
            return self.interned.strings[idx]
        return f"<str:{idx}>"

    def interned_dname(self, idx: int) -> str:
        if 0 <= idx < len(self.interned.dotted_names):
            return self.interned.dotted_names[idx]
        return f"<dname:{idx}>"

    def dotted_name(self, segments: list[str]) -> str:
        return ".".join(segments)

    def fqn_with_package(self, pkg_id: str, module: str, name: str) -> str:
        if not module:
            return name
        if pkg_id == self.package_id:
            return f"{module}.{name}"
        return f"{pkg_id}:{module}.{name}"


class Lf1Resolver(LfResolverBase):
    def resolve_package_ref(self, pkg_ref: Any) -> str:
        which = pkg_ref.WhichOneof("Sum")
        if which == "self":
            return self.package_id
        if which == "package_id_str":
            return pkg_ref.package_id_str
        if which == "package_id_interned_str":
            return self.interned_str(pkg_ref.package_id_interned_str)
        return "<pkg:unknown>"

    def resolve_module_ref(self, module_ref: Any) -> ResolvedName:
        pkg_id = self.resolve_package_ref(module_ref.package_ref)
        which = module_ref.WhichOneof("module_name")
        if which == "module_name_dname":
            name = self.dotted_name(list(module_ref.module_name_dname.segments))
        else:
            name = self.interned_dname(module_ref.module_name_interned_dname)
        return ResolvedName(package_id=pkg_id, module=name, name="")

    def resolve_type_con(self, tycon: Any) -> ResolvedName:
        mod = self.resolve_module_ref(tycon.module)
        which = tycon.WhichOneof("name")
        if which == "name_dname":
            name = self.dotted_name(list(tycon.name_dname.segments))
        else:
            name = self.interned_dname(tycon.name_interned_dname)
        return ResolvedName(package_id=mod.package_id, module=mod.module, name=name)

    def resolve_val_name(self, val: Any) -> ResolvedName:
        mod = self.resolve_module_ref(val.module)
        if val.name_dname:
            name = self.dotted_name(list(val.name_dname))
        else:
            name = self.interned_dname(val.name_interned_dname)
        return ResolvedName(package_id=mod.package_id, module=mod.module, name=name)

    def resolve_identifier(self, name_str: str | None, name_interned: int | None) -> str:
        if name_str is not None and name_str != "":
            return name_str
        if name_interned is not None:
            return self.interned_str(name_interned)
        return "<id>"


class Lf2Resolver(LfResolverBase):
    def resolve_package_id(self, pkg_id: Any) -> str:
        which = pkg_id.WhichOneof("Sum")
        if which == "self_package_id":
            return self.package_id
        if which == "imported_package_id_interned_str":
            return self.interned_str(pkg_id.imported_package_id_interned_str)
        if which == "package_import_id":
            idx = pkg_id.package_import_id
            if 0 <= idx < len(self.interned.imports):
                return self.interned.imports[idx]
            return f"<import:{idx}>"
        return "<pkg:unknown>"

    def resolve_module_id(self, module_id: Any) -> ResolvedName:
        pkg_id = self.resolve_package_id(module_id.package_id)
        name = self.interned_dname(module_id.module_name_interned_dname)
        return ResolvedName(package_id=pkg_id, module=name, name="")

    def resolve_type_con(self, tycon: Any) -> ResolvedName:
        mod = self.resolve_module_id(tycon.module)
        name = self.interned_dname(tycon.name_interned_dname)
        return ResolvedName(package_id=mod.package_id, module=mod.module, name=name)

    def resolve_val_name(self, val: Any) -> ResolvedName:
        mod = self.resolve_module_id(val.module)
        name = self.interned_dname(val.name_interned_dname)
        return ResolvedName(package_id=mod.package_id, module=mod.module, name=name)

    def resolve_identifier(self, name_interned: int) -> str:
        return self.interned_str(name_interned)
