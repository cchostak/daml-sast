"""
Generate tiny DAR fixtures used for manual testing.

Outputs files into the target directory (default: testdata/external/dars):
- sample-findings.dar        : triggers DAML-AUTH-001, DAML-LIFE-001
- sample-clean.dar           : zero findings
- sample-uncontrolled.dar    : triggers DAML-AUTH-002 (unknown controllers)
- sample-empty-sigs.dar      : triggers DAML-AUTH-003 (no signatories)
- sample-create-any.dar      : triggers DAML-LIFE-002 (nonconsuming create other template)
- sample-forward-exercise.dar: triggers DAML-AUTH-004 (nonconsuming forwarding exercise)
"""

from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path

from daml_sast.lf.proto.com.digitalasset.daml.lf.archive import daml_lf1_pb2, daml_lf_pb2


def _archive_from_package(pkg: daml_lf1_pb2.Package) -> bytes:
    payload = daml_lf_pb2.ArchivePayload()
    payload.minor = "7"
    payload.patch = 0
    payload.daml_lf_1 = pkg.SerializeToString()

    payload_bytes = payload.SerializeToString()
    archive = daml_lf_pb2.Archive()
    archive.hash_function = daml_lf_pb2.SHA256
    archive.payload = payload_bytes
    archive.hash = hashlib.sha256(payload_bytes).hexdigest()
    return archive.SerializeToString()


def _write_zip(path: Path, dalf_name: str, archive_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(dalf_name, archive_bytes)


def _expr_party_list(parties, party_type, list_party_type, s_idx):
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


def _expr_party_var(var, s_idx):
    expr = daml_lf1_pb2.Expr()
    expr.var_interned_str = s_idx(var)
    return expr


def _expr_let_list(var, parties, list_party_type, s_idx):
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


def _expr_update_pure_unit(unit_type):
    expr = daml_lf1_pb2.Expr()
    expr.update.pure.type.CopyFrom(unit_type)
    unit_expr = daml_lf1_pb2.Expr()
    unit_expr.prim_con = daml_lf1_pb2.CON_UNIT
    expr.update.pure.expr.CopyFrom(unit_expr)
    return expr


def _expr_update_create(module_dn, template_dn):
    expr = daml_lf1_pb2.Expr()
    create = expr.update.create

    tcn = daml_lf1_pb2.TypeConName()
    tcn.module.package_ref.self.CopyFrom(daml_lf1_pb2.Unit())
    tcn.module.module_name_interned_dname = module_dn
    tcn.name_interned_dname = template_dn
    create.template.CopyFrom(tcn)

    unit_expr = daml_lf1_pb2.Expr()
    unit_expr.prim_con = daml_lf1_pb2.CON_UNIT
    create.expr.CopyFrom(unit_expr)
    return expr


def _expr_update_exercise(module_dn, template_dn, choice_dn, cid_var, arg_var):
    expr = daml_lf1_pb2.Expr()
    exercise = expr.update.exercise

    tcn = daml_lf1_pb2.TypeConName()
    tcn.module.package_ref.self.CopyFrom(daml_lf1_pb2.Unit())
    tcn.module.module_name_interned_dname = module_dn
    tcn.name_interned_dname = template_dn
    exercise.template.CopyFrom(tcn)
    exercise.choice_interned_str = choice_dn

    cid_expr = daml_lf1_pb2.Expr()
    cid_expr.var_interned_str = cid_var
    exercise.cid.CopyFrom(cid_expr)

    arg_expr = daml_lf1_pb2.Expr()
    arg_expr.var_interned_str = arg_var
    exercise.arg.CopyFrom(arg_expr)
    return expr


def build_pkg_with_findings() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments):
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in ["Main", "TAuth", "TNonConsume", "Transfer", "Mint", "this", "arg", "self", "sigs", "Alice", "Bob", "TestPkg", "0.0.0"]:
        s_idx(s)
    pkg.interned_strings.extend(strings)

    main_dn = add_dname(["Main"])
    tauth_dn = add_dname(["TAuth"])
    tnon_dn = add_dname(["TNonConsume"])

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


def build_pkg_uncontrolled_controllers() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments):
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in ["Main", "TFreeCtrl", "Do", "this", "arg", "self", "Alice", "TestPkg", "0.0.0"]:
        s_idx(s)
    pkg.interned_strings.extend(strings)

    main_dn = add_dname(["Main"])
    tfree_dn = add_dname(["TFreeCtrl"])

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

    tmpl = mod.templates.add()
    tmpl.tycon_interned_dname = tfree_dn
    tmpl.param_interned_str = s_idx("this")
    tmpl.signatories.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    tmpl.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    choice = tmpl.choices.add()
    choice.name_interned_str = s_idx("Do")
    choice.consuming = False
    # Controllers from choice argument (uncontrolled)
    choice.controllers.CopyFrom(_expr_party_var("arg", s_idx))
    choice.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    choice.arg_binder.var_interned_str = s_idx("arg")
    choice.arg_binder.type.CopyFrom(party_type)
    choice.ret_type.CopyFrom(unit_type)
    choice.self_binder_interned_str = s_idx("self")
    choice.update.CopyFrom(_expr_update_pure_unit(unit_type))
    return pkg


def build_pkg_empty_signatories() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments):
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in ["Main", "TEmpty", "Do", "this", "arg", "self", "TestPkg", "0.0.0"]:
        s_idx(s)
    pkg.interned_strings.extend(strings)

    main_dn = add_dname(["Main"])
    tempty_dn = add_dname(["TEmpty"])

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

    tmpl = mod.templates.add()
    tmpl.tycon_interned_dname = tempty_dn
    tmpl.param_interned_str = s_idx("this")
    tmpl.signatories.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))  # empty
    tmpl.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    choice = tmpl.choices.add()
    choice.name_interned_str = s_idx("Do")
    choice.consuming = False
    choice.controllers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    choice.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    choice.arg_binder.var_interned_str = s_idx("arg")
    choice.arg_binder.type.CopyFrom(party_type)
    choice.ret_type.CopyFrom(unit_type)
    choice.self_binder_interned_str = s_idx("self")
    choice.update.CopyFrom(_expr_update_pure_unit(unit_type))
    return pkg


def build_pkg_create_other() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments):
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in ["Main", "Spawner", "Child", "Spawn", "this", "arg", "self", "Alice", "TestPkg", "0.0.0"]:
        s_idx(s)
    pkg.interned_strings.extend(strings)

    main_dn = add_dname(["Main"])
    spawner_dn = add_dname(["Spawner"])
    child_dn = add_dname(["Child"])

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

    # Child template (unused choice)
    child = mod.templates.add()
    child.tycon_interned_dname = child_dn
    child.param_interned_str = s_idx("this")
    child.signatories.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    child.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    # Spawner that creates Child in nonconsuming choice
    spawner = mod.templates.add()
    spawner.tycon_interned_dname = spawner_dn
    spawner.param_interned_str = s_idx("this")
    spawner.signatories.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    spawner.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    c_spawn = spawner.choices.add()
    c_spawn.name_interned_str = s_idx("Spawn")
    c_spawn.consuming = False
    c_spawn.controllers.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    c_spawn.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    c_spawn.arg_binder.var_interned_str = s_idx("arg")
    c_spawn.arg_binder.type.CopyFrom(party_type)
    c_spawn.ret_type.CopyFrom(unit_type)
    c_spawn.self_binder_interned_str = s_idx("self")
    c_spawn.update.CopyFrom(_expr_update_create(main_dn, child_dn))
    return pkg


def build_pkg_forward_exercise() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments):
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in ["Main", "TForward", "TTarget", "Forward", "Do", "this", "arg", "self", "cid", "Alice", "Bob", "TestPkg", "0.0.0"]:
        s_idx(s)
    pkg.interned_strings.extend(strings)

    main_dn = add_dname(["Main"])
    fwd_dn = add_dname(["TForward"])
    tgt_dn = add_dname(["TTarget"])

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

    tgt = mod.templates.add()
    tgt.tycon_interned_dname = tgt_dn
    tgt.param_interned_str = s_idx("this")
    tgt.signatories.CopyFrom(_expr_party_list(["Bob"], party_type, list_party_type, s_idx))
    tgt.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    # Target choice doing nothing
    tgt_choice = tgt.choices.add()
    tgt_choice.name_interned_str = s_idx("Do")
    tgt_choice.consuming = True
    tgt_choice.controllers.CopyFrom(_expr_party_list(["Bob"], party_type, list_party_type, s_idx))
    tgt_choice.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    tgt_choice.arg_binder.var_interned_str = s_idx("arg")
    tgt_choice.arg_binder.type.CopyFrom(party_type)
    tgt_choice.ret_type.CopyFrom(unit_type)
    tgt_choice.self_binder_interned_str = s_idx("self")
    tgt_choice.update.CopyFrom(_expr_update_pure_unit(unit_type))

    fwd = mod.templates.add()
    fwd.tycon_interned_dname = fwd_dn
    fwd.param_interned_str = s_idx("this")
    fwd.signatories.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    fwd.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))

    fwd_choice = fwd.choices.add()
    fwd_choice.name_interned_str = s_idx("Forward")
    fwd_choice.consuming = False
    fwd_choice.controllers.CopyFrom(_expr_party_list(["Alice"], party_type, list_party_type, s_idx))
    fwd_choice.observers.CopyFrom(_expr_party_list([], party_type, list_party_type, s_idx))
    fwd_choice.arg_binder.var_interned_str = s_idx("arg")
    fwd_choice.arg_binder.type.CopyFrom(party_type)
    fwd_choice.ret_type.CopyFrom(unit_type)
    fwd_choice.self_binder_interned_str = s_idx("self")
    # Assume cid variable is provided; for minimal sample, reuse self as cid
    fwd_choice.update.CopyFrom(_expr_update_exercise(main_dn, tgt_dn, s_idx("Do"), s_idx("self"), s_idx("arg")))
    return pkg
def build_pkg_no_findings() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    def add_dname(segments):
        dname = pkg.interned_dotted_names.add()
        dname.segments_interned_str.extend([s_idx(seg) for seg in segments])
        return len(pkg.interned_dotted_names) - 1

    for s in ["Main", "TSafe", "Do", "this", "arg", "self", "Alice", "TestPkg", "0.0.0"]:
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="testdata/external/dars", help="Output directory for generated DARs")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    archive_with = _archive_from_package(build_pkg_with_findings())
    archive_without = _archive_from_package(build_pkg_no_findings())
    archive_uncontrolled = _archive_from_package(build_pkg_uncontrolled_controllers())
    archive_empty = _archive_from_package(build_pkg_empty_signatories())
    archive_create_any = _archive_from_package(build_pkg_create_other())
    archive_forward = _archive_from_package(build_pkg_forward_exercise())

    _write_zip(out_dir / "sample-findings.dar", "rules.dalf", archive_with)
    _write_zip(out_dir / "sample-clean.dar", "rules-negative.dalf", archive_without)
    _write_zip(out_dir / "sample-uncontrolled.dar", "uncontrolled.dalf", archive_uncontrolled)
    _write_zip(out_dir / "sample-empty-sigs.dar", "empty-sigs.dalf", archive_empty)
    _write_zip(out_dir / "sample-create-any.dar", "create-any.dalf", archive_create_any)
    _write_zip(out_dir / "sample-forward-exercise.dar", "forward-exercise.dalf", archive_forward)

    print(f"Wrote fixtures to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
