from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from daml_sast.engine.runner import run
from daml_sast.lf.loader import load_program_from_dar
from daml_sast.lf.proto.com.digitalasset.daml.lf.archive import daml_lf1_pb2, daml_lf_pb2
from daml_sast.rules.registry import registry


class RuleDalfTests(unittest.TestCase):
    def test_rules_on_lf1_dar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dar_path = Path(tmp) / "rules.dar"
            _write_lf1_dar(dar_path)

            program = load_program_from_dar(str(dar_path))
            findings = run(registry(), program)
            ids = {f.id for f in findings}

        self.assertIn("DAML-AUTH-001", ids)
        self.assertIn("DAML-LIFE-001", ids)

    def test_rules_negative_on_lf1_dar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dar_path = Path(tmp) / "rules-negative.dar"
            _write_lf1_dar_no_findings(dar_path)

            program = load_program_from_dar(str(dar_path))
            findings = run(registry(), program)

        self.assertEqual([], findings)


# --- Helpers to build a minimal LF1 DAR with rule triggers ---


def _write_lf1_dar(path: Path) -> None:
    pkg = _build_lf1_package()
    payload = daml_lf_pb2.ArchivePayload()
    payload.minor = "7"
    payload.patch = 0
    payload.daml_lf_1 = pkg.SerializeToString()

    payload_bytes = payload.SerializeToString()
    archive = daml_lf_pb2.Archive()
    archive.hash_function = daml_lf_pb2.SHA256
    archive.payload = payload_bytes
    archive.hash = hashlib.sha256(payload_bytes).hexdigest()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("rules.dalf", archive.SerializeToString())


def _write_lf1_dar_no_findings(path: Path) -> None:
    pkg = _build_lf1_package_no_findings()
    payload = daml_lf_pb2.ArchivePayload()
    payload.minor = "7"
    payload.patch = 0
    payload.daml_lf_1 = pkg.SerializeToString()

    payload_bytes = payload.SerializeToString()
    archive = daml_lf_pb2.Archive()
    archive.hash_function = daml_lf_pb2.SHA256
    archive.payload = payload_bytes
    archive.hash = hashlib.sha256(payload_bytes).hexdigest()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("rules-negative.dalf", archive.SerializeToString())


def _build_lf1_package() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()

    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments: list[str]) -> int:
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    # interned strings
    for s in [
        "Main",
        "TAuth",
        "TNonConsume",
        "Transfer",
        "Mint",
        "this",
        "arg",
        "self",
        "sigs",
        "Alice",
        "Bob",
        "TestPkg",
        "0.0.0",
    ]:
        s_idx(s)

    pkg.interned_strings.extend(strings)

    # dotted names
    main_dn = add_dname(["Main"])
    tauth_dn = add_dname(["TAuth"])
    tnon_dn = add_dname(["TNonConsume"])

    # metadata
    pkg.metadata.name_interned_str = s_idx("TestPkg")
    pkg.metadata.version_interned_str = s_idx("0.0.0")

    # module
    mod = pkg.modules.add()
    mod.name_interned_dname = main_dn

    # types
    party_type = daml_lf1_pb2.Type()
    party_type.prim.prim = daml_lf1_pb2.PARTY

    unit_type = daml_lf1_pb2.Type()
    unit_type.prim.prim = daml_lf1_pb2.UNIT

    list_party_type = daml_lf1_pb2.Type()
    list_party_type.prim.prim = daml_lf1_pb2.LIST
    list_party_type.prim.args.extend([party_type])

    # Template: TAuth (controllers not aligned)
    t_auth = mod.templates.add()
    t_auth.tycon_interned_dname = tauth_dn
    t_auth.param_interned_str = s_idx("this")
    t_auth.signatories.CopyFrom(_expr_let_list("sigs", ["Alice"], list_party_type, s_idx))
    t_auth.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    c_auth = t_auth.choices.add()
    c_auth.name_interned_str = s_idx("Transfer")
    c_auth.consuming = True
    c_auth.controllers.CopyFrom(_expr_party_list(["Bob"], party_type, list_party_type, s_idx))
    c_auth.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    c_auth.arg_binder.var_interned_str = s_idx("arg")
    c_auth.arg_binder.type.CopyFrom(party_type)
    c_auth.ret_type.CopyFrom(unit_type)
    c_auth.self_binder_interned_str = s_idx("self")
    c_auth.update.CopyFrom(_expr_update_pure_unit(unit_type))

    # Template: TNonConsume (nonconsuming create)
    t_non = mod.templates.add()
    t_non.tycon_interned_dname = tnon_dn
    t_non.param_interned_str = s_idx("this")
    t_non.signatories.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    t_non.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    c_non = t_non.choices.add()
    c_non.name_interned_str = s_idx("Mint")
    c_non.consuming = False
    c_non.controllers.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    c_non.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    c_non.arg_binder.var_interned_str = s_idx("arg")
    c_non.arg_binder.type.CopyFrom(party_type)
    c_non.ret_type.CopyFrom(unit_type)
    c_non.self_binder_interned_str = s_idx("self")
    c_non.update.CopyFrom(_expr_update_create(main_dn, tnon_dn))

    return pkg


def _build_lf1_package_no_findings() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()

    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments: list[str]) -> int:
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in [
        "Main",
        "TSafe",
        "Do",
        "this",
        "arg",
        "self",
        "Alice",
        "TestPkg",
        "0.0.0",
    ]:
        s_idx(s)

    pkg.interned_strings.extend(strings)

    main_dn = add_dname(["Main"])
    tsafe_dn = add_dname(["TSafe"])

    pkg.metadata.name_interned_str = s_idx("TestPkg")
    pkg.metadata.version_interned_str = s_idx("0.0.0")

    mod = pkg.modules.add()
    mod.name_interned_dname = main_dn

    party_type = daml_lf1_pb2.Type()
    party_type.prim.prim = daml_lf1_pb2.PARTY

    unit_type = daml_lf1_pb2.Type()
    unit_type.prim.prim = daml_lf1_pb2.UNIT

    list_party_type = daml_lf1_pb2.Type()
    list_party_type.prim.prim = daml_lf1_pb2.LIST
    list_party_type.prim.args.extend([party_type])

    t_safe = mod.templates.add()
    t_safe.tycon_interned_dname = tsafe_dn
    t_safe.param_interned_str = s_idx("this")
    t_safe.signatories.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    t_safe.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    c_safe = t_safe.choices.add()
    c_safe.name_interned_str = s_idx("Do")
    c_safe.consuming = False
    c_safe.controllers.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    c_safe.arg_binder.var_interned_str = s_idx("arg")
    c_safe.arg_binder.type.CopyFrom(party_type)
    c_safe.ret_type.CopyFrom(unit_type)
    c_safe.self_binder_interned_str = s_idx("self")
    c_safe.update.CopyFrom(_expr_update_pure_unit(unit_type))

    return pkg


def _expr_party_list(
    parties: list[str],
    party_type: daml_lf1_pb2.Type,
    list_party_type: daml_lf1_pb2.Type,
    s_idx,
) -> daml_lf1_pb2.Expr:
    if not parties:
        expr = daml_lf1_pb2.Expr()
        expr.nil.type.CopyFrom(party_type)
        return expr

    nil_expr = daml_lf1_pb2.Expr()
    nil_expr.nil.type.CopyFrom(party_type)

    cons_expr = daml_lf1_pb2.Expr()
    cons_expr.cons.type.CopyFrom(party_type)
    for p in parties:
        lit = daml_lf1_pb2.Expr()
        lit.prim_lit.party_interned_str = s_idx(p)
        cons_expr.cons.front.append(lit)
    cons_expr.cons.tail.CopyFrom(nil_expr)
    return cons_expr


def _expr_let_list(
    var: str,
    parties: list[str],
    list_party_type: daml_lf1_pb2.Type,
    s_idx,
) -> daml_lf1_pb2.Expr:
    block = daml_lf1_pb2.Block()
    binding = block.bindings.add()
    binding.binder.var_interned_str = s_idx(var)
    binding.binder.type.CopyFrom(list_party_type)
    binding.bound.CopyFrom(_expr_party_list(parties, list_party_type.prim.args[0], list_party_type, s_idx))

    body = daml_lf1_pb2.Expr()
    body.var_interned_str = s_idx(var)
    block.body.CopyFrom(body)

    expr = daml_lf1_pb2.Expr()
    expr.let.CopyFrom(block)
    return expr


def _expr_update_pure_unit(unit_type: daml_lf1_pb2.Type) -> daml_lf1_pb2.Expr:
    expr = daml_lf1_pb2.Expr()
    expr.update.pure.type.CopyFrom(unit_type)
    unit_expr = daml_lf1_pb2.Expr()
    unit_expr.prim_con = daml_lf1_pb2.CON_UNIT
    expr.update.pure.expr.CopyFrom(unit_expr)
    return expr


def _expr_update_create(module_dn: int, template_dn: int) -> daml_lf1_pb2.Expr:
    expr = daml_lf1_pb2.Expr()
    create = expr.update.create

    # TypeConName
    tcn = daml_lf1_pb2.TypeConName()
    tcn.module.package_ref.self.CopyFrom(daml_lf1_pb2.Unit())
    tcn.module.module_name_interned_dname = module_dn
    tcn.name_interned_dname = template_dn
    create.template.CopyFrom(tcn)

    unit_expr = daml_lf1_pb2.Expr()
    unit_expr.prim_con = daml_lf1_pb2.CON_UNIT
    create.expr.CopyFrom(unit_expr)
    return expr


if __name__ == "__main__":
    unittest.main()
