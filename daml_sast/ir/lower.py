# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from daml_sast.ir.model import (
    Choice,
    Expr,
    Location,
    Module,
    Package,
    Program,
    SourceSpan,
    Template,
    TemplateKey,
    Type,
    ValueDef,
)
from daml_sast.lf.decoder import LfPackage
from daml_sast.lf.resolve import Lf1Resolver, Lf2Resolver
from daml_sast.lf.proto.com.digitalasset.daml.lf.archive import daml_lf1_pb2, daml_lf2_pb2


class LoweringError(ValueError):
    pass


def lower_packages(packages: list[LfPackage]) -> Program:
    ir_packages: list[Package] = []
    for pkg in packages:
        if pkg.lf_major == 1:
            resolver = Lf1Resolver(pkg.package_id, pkg.interned)
            modules = _lower_lf1_modules(pkg, resolver)
        elif pkg.lf_major == 2:
            resolver = Lf2Resolver(pkg.package_id, pkg.interned)
            modules = _lower_lf2_modules(pkg, resolver)
        else:
            raise LoweringError(f"Unsupported LF major {pkg.lf_major}")
        ir_packages.append(
            Package(
                package_id=pkg.package_id,
                name=pkg.name,
                version=pkg.version,
                modules=modules,
                lf_ref=f"pkg:{pkg.package_id}",
            )
        )
    return Program(packages=ir_packages)


# --- LF1 lowering ---


def _lower_lf1_modules(pkg: LfPackage, resolver: Lf1Resolver) -> list[Module]:
    out: list[Module] = []
    for mod in pkg.lf_package.modules:
        module_name = _lf1_module_name(mod, resolver)
        templates = [
            _lower_lf1_template(t, resolver, module_name, pkg.package_id) for t in mod.templates
        ]
        values = [
            _lower_lf1_value(v, resolver, module_name, pkg.package_id) for v in mod.values
        ]
        out.append(
            Module(
                name=module_name,
                templates=templates,
                values=values,
                location=None,
                lf_ref=f"mod:{module_name}",
            )
        )
    return out


def _lf1_module_name(mod: daml_lf1_pb2.Module, resolver: Lf1Resolver) -> str:
    which = mod.WhichOneof("name")
    if which == "name_dname":
        return resolver.dotted_name(list(mod.name_dname.segments))
    if which == "name_interned_dname":
        return resolver.interned_dname(mod.name_interned_dname)
    return "<module>"


def _lower_lf1_template(
    tmpl: daml_lf1_pb2.DefTemplate,
    resolver: Lf1Resolver,
    module_name: str,
    package_id: str,
) -> Template:
    which = tmpl.WhichOneof("tycon")
    if which == "tycon_dname":
        name = resolver.dotted_name(list(tmpl.tycon_dname.segments))
    else:
        name = resolver.interned_dname(tmpl.tycon_interned_dname)
    template_name = f"{module_name}.{name}"

    param_name = resolver.resolve_identifier(
        tmpl.param_str if tmpl.HasField("param_str") else None,
        tmpl.param_interned_str if tmpl.HasField("param_interned_str") else None,
    )
    env = {param_name: Type(kind="con", name=template_name)}

    signatories = _lower_expr_lf1(tmpl.signatories, resolver, env, module_name, package_id)
    observers = _lower_expr_lf1(tmpl.observers, resolver, env, module_name, package_id)
    precond = None
    if tmpl.HasField("precond"):
        precond = _lower_expr_lf1(tmpl.precond, resolver, env, module_name, package_id)

    key = None
    if tmpl.HasField("key"):
        key = _lower_lf1_key(tmpl.key, resolver, env, module_name, package_id)

    choices = [
        _lower_lf1_choice(c, resolver, env, module_name, package_id, template_name)
        for c in tmpl.choices
    ]

    location = _lower_location_lf1(tmpl.location, resolver, module_name, f"Template {template_name}")
    return Template(
        name=template_name,
        params=[param_name],
        signatories=signatories,
        observers=observers,
        key=key,
        choices=choices,
        precond=precond,
        location=location,
        lf_ref=f"tmpl:{template_name}",
    )


def _lower_lf1_key(
    key: daml_lf1_pb2.DefTemplate.DefKey,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> TemplateKey:
    typ = _lower_type_lf1(key.type, resolver)
    if key.HasField("complex_key"):
        body = _lower_expr_lf1(key.complex_key, resolver, env, module_name, package_id)
    else:
        body = _lower_keyexpr_lf1(key.key, resolver, env, module_name, package_id)
    maintainers = _lower_expr_lf1(key.maintainers, resolver, env, module_name, package_id)
    return TemplateKey(typ=typ, body=body, maintainers=maintainers, lf_ref=None)


def _lower_keyexpr_lf1(
    key_expr: daml_lf1_pb2.KeyExpr,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> Expr:
    which = key_expr.WhichOneof("Sum")
    if which == "projections":
        fields = []
        for proj in key_expr.projections.projections:
            field_name = resolver.resolve_identifier(
                proj.field_str if proj.HasField("field_str") else None,
                proj.field_interned_str if proj.HasField("field_interned_str") else None,
            )
            fields.append(Expr(kind="field", value=field_name))
        return Expr(kind="key.projections", children=fields)
    if which == "record":
        fields = []
        for fld in key_expr.record.fields:
            field_name = resolver.resolve_identifier(
                fld.field_str if fld.HasField("field_str") else None,
                fld.field_interned_str if fld.HasField("field_interned_str") else None,
            )
            child = _lower_keyexpr_lf1(fld.expr, resolver, env, module_name, package_id)
            fields.append(Expr(kind="field", value=field_name, children=[child]))
        return Expr(kind="key.record", children=fields)
    return Expr(kind="key.unknown")


def _lower_lf1_choice(
    choice: daml_lf1_pb2.TemplateChoice,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
    template_name: str,
) -> Choice:
    which = choice.WhichOneof("name")
    if which == "name_str":
        name = choice.name_str
    else:
        name = resolver.interned_str(choice.name_interned_str)

    arg_name = _lower_var_with_type_name_lf1(choice.arg_binder, resolver)
    arg_type = _lower_type_lf1(choice.arg_binder.type, resolver)
    env_with_arg = {**env, arg_name: arg_type}

    controllers = _lower_expr_lf1(choice.controllers, resolver, env_with_arg, module_name, package_id)
    observers = None
    if choice.HasField("observers"):
        observers = _lower_expr_lf1(choice.observers, resolver, env_with_arg, module_name, package_id)

    authorizers = None
    if choice.HasField("authorizers"):
        authorizers = _lower_expr_lf1(choice.authorizers, resolver, env_with_arg, module_name, package_id)

    update = _lower_expr_lf1(choice.update, resolver, env_with_arg, module_name, package_id)
    ret_type = _lower_type_lf1(choice.ret_type, resolver)

    location = _lower_location_lf1(choice.location, resolver, module_name, f"Choice {name}")
    return Choice(
        name=name,
        consuming=choice.consuming,
        controllers=controllers,
        observers=observers,
        authorizers=authorizers,
        return_type=ret_type,
        update=update,
        location=location,
        lf_ref=f"choice:{template_name}:{name}",
    )


def _lower_lf1_value(
    val: daml_lf1_pb2.DefValue,
    resolver: Lf1Resolver,
    module_name: str,
    package_id: str,
) -> ValueDef:
    name = "<value>"
    if val.name_with_type.name_dname:
        name = resolver.dotted_name(list(val.name_with_type.name_dname))
    else:
        name = resolver.interned_dname(val.name_with_type.name_interned_dname)
    typ = _lower_type_lf1(val.name_with_type.type, resolver)
    body = _lower_expr_lf1(val.expr, resolver, {}, module_name, package_id)
    return ValueDef(name=f"{module_name}.{name}", typ=typ, body=body, lf_ref=f"val:{name}")


# --- LF2 lowering ---


def _lower_lf2_modules(pkg: LfPackage, resolver: Lf2Resolver) -> list[Module]:
    out: list[Module] = []
    for mod in pkg.lf_package.modules:
        module_name = resolver.interned_dname(mod.name_interned_dname)
        templates = [
            _lower_lf2_template(t, resolver, module_name, pkg.package_id) for t in mod.templates
        ]
        values = [
            _lower_lf2_value(v, resolver, module_name, pkg.package_id) for v in mod.values
        ]
        out.append(
            Module(
                name=module_name,
                templates=templates,
                values=values,
                location=None,
                lf_ref=f"mod:{module_name}",
            )
        )
    return out


def _lower_lf2_template(
    tmpl: daml_lf2_pb2.DefTemplate,
    resolver: Lf2Resolver,
    module_name: str,
    package_id: str,
) -> Template:
    name = resolver.interned_dname(tmpl.tycon_interned_dname)
    template_name = f"{module_name}.{name}"

    param_name = resolver.resolve_identifier(tmpl.param_interned_str)
    env = {param_name: Type(kind="con", name=template_name)}

    signatories = _lower_expr_lf2(tmpl.signatories, resolver, env, module_name, package_id)
    observers = _lower_expr_lf2(tmpl.observers, resolver, env, module_name, package_id)
    precond = None
    if tmpl.HasField("precond"):
        precond = _lower_expr_lf2(tmpl.precond, resolver, env, module_name, package_id)

    key = None
    if tmpl.HasField("key"):
        key = _lower_lf2_key(tmpl.key, resolver, env, module_name, package_id)

    choices = [
        _lower_lf2_choice(c, resolver, env, module_name, package_id, template_name)
        for c in tmpl.choices
    ]

    location = _lower_location_lf2(tmpl.location, resolver, module_name, f"Template {template_name}")
    return Template(
        name=template_name,
        params=[param_name],
        signatories=signatories,
        observers=observers,
        key=key,
        choices=choices,
        precond=precond,
        location=location,
        lf_ref=f"tmpl:{template_name}",
    )


def _lower_lf2_key(
    key: daml_lf2_pb2.DefTemplate.DefKey,
    resolver: Lf2Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> TemplateKey:
    typ = _lower_type_lf2(key.type, resolver)
    if key.HasField("complex_key"):
        body = _lower_expr_lf2(key.complex_key, resolver, env, module_name, package_id)
    else:
        body = _lower_keyexpr_lf2(key.key, resolver, env, module_name, package_id)
    maintainers = _lower_expr_lf2(key.maintainers, resolver, env, module_name, package_id)
    return TemplateKey(typ=typ, body=body, maintainers=maintainers, lf_ref=None)


def _lower_keyexpr_lf2(
    key_expr: daml_lf2_pb2.KeyExpr,
    resolver: Lf2Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> Expr:
    which = key_expr.WhichOneof("Sum")
    if which == "projections":
        fields = []
        for proj in key_expr.projections.projections:
            field_name = resolver.resolve_identifier(proj.field_interned_str)
            fields.append(Expr(kind="field", value=field_name))
        return Expr(kind="key.projections", children=fields)
    if which == "record":
        fields = []
        for fld in key_expr.record.fields:
            field_name = resolver.resolve_identifier(fld.field_interned_str)
            child = _lower_keyexpr_lf2(fld.expr, resolver, env, module_name, package_id)
            fields.append(Expr(kind="field", value=field_name, children=[child]))
        return Expr(kind="key.record", children=fields)
    return Expr(kind="key.unknown")


def _lower_lf2_choice(
    choice: daml_lf2_pb2.TemplateChoice,
    resolver: Lf2Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
    template_name: str,
) -> Choice:
    name = resolver.resolve_identifier(choice.name_interned_str)

    arg_name = resolver.resolve_identifier(choice.arg_binder.var_interned_str)
    arg_type = _lower_type_lf2(choice.arg_binder.type, resolver)
    env_with_arg = {**env, arg_name: arg_type}

    controllers = _lower_expr_lf2(choice.controllers, resolver, env_with_arg, module_name, package_id)
    observers = None
    if choice.HasField("observers"):
        observers = _lower_expr_lf2(choice.observers, resolver, env_with_arg, module_name, package_id)

    authorizers = None
    if choice.HasField("authorizers"):
        authorizers = _lower_expr_lf2(choice.authorizers, resolver, env_with_arg, module_name, package_id)

    update = _lower_expr_lf2(choice.update, resolver, env_with_arg, module_name, package_id)
    ret_type = _lower_type_lf2(choice.ret_type, resolver)

    location = _lower_location_lf2(choice.location, resolver, module_name, f"Choice {name}")
    return Choice(
        name=name,
        consuming=choice.consuming,
        controllers=controllers,
        observers=observers,
        authorizers=authorizers,
        return_type=ret_type,
        update=update,
        location=location,
        lf_ref=f"choice:{template_name}:{name}",
    )


def _lower_lf2_value(
    val: daml_lf2_pb2.DefValue,
    resolver: Lf2Resolver,
    module_name: str,
    package_id: str,
) -> ValueDef:
    name = resolver.interned_dname(val.name_with_type.name_interned_dname)
    typ = _lower_type_lf2(val.name_with_type.type, resolver)
    body = _lower_expr_lf2(val.expr, resolver, {}, module_name, package_id)
    return ValueDef(name=f"{module_name}.{name}", typ=typ, body=body, lf_ref=f"val:{name}")


# --- Common helpers ---


def _lower_var_with_type_name_lf1(var: daml_lf1_pb2.VarWithType, resolver: Lf1Resolver) -> str:
    if var.var_str:
        return var.var_str
    return resolver.interned_str(var.var_interned_str)


def _lower_location_lf1(loc: daml_lf1_pb2.Location, resolver: Lf1Resolver, module: str, definition: str) -> Location:
    if loc is None:
        return Location(module=module, definition=definition)
    mod_name = module
    try:
        if loc.HasField("module"):
            mod = resolver.resolve_module_ref(loc.module)
            mod_name = mod.module
    except ValueError:
        pass
    span = None
    if loc.HasField("range"):
        span = SourceSpan(
            file=None,
            start_line=loc.range.start_line + 1,
            start_col=loc.range.start_col + 1,
            end_line=loc.range.end_line + 1,
            end_col=loc.range.end_col + 1,
        )
    return Location(module=mod_name, definition=definition, span=span)


def _lower_location_lf2(loc: daml_lf2_pb2.Location, resolver: Lf2Resolver, module: str, definition: str) -> Location:
    if loc is None:
        return Location(module=module, definition=definition)
    mod_name = module
    try:
        if loc.HasField("module"):
            mod = resolver.resolve_module_id(loc.module)
            mod_name = mod.module
    except ValueError:
        pass
    span = None
    if loc.HasField("range"):
        span = SourceSpan(
            file=None,
            start_line=loc.range.start_line + 1,
            start_col=loc.range.start_col + 1,
            end_line=loc.range.end_line + 1,
            end_col=loc.range.end_col + 1,
        )
    return Location(module=mod_name, definition=definition, span=span)


def _lower_type_lf1(typ: daml_lf1_pb2.Type, resolver: Lf1Resolver) -> Type:
    if typ is None:
        return Type(kind="unknown")
    which = typ.WhichOneof("Sum")
    if which == "interned":
        idx = typ.interned
        if 0 <= idx < len(resolver.interned.types):
            return _lower_type_lf1(resolver.interned.types[idx], resolver)
        return Type(kind="unknown")
    if which == "var":
        name = resolver.resolve_identifier(
            typ.var.var_str if typ.var.HasField("var_str") else None,
            typ.var.var_interned_str if typ.var.HasField("var_interned_str") else None,
        )
        args = [_lower_type_lf1(a, resolver) for a in typ.var.args]
        return Type(kind="var", name=name, args=args)
    if which == "con":
        name = resolver.resolve_type_con(typ.con.tycon)
        args = [_lower_type_lf1(a, resolver) for a in typ.con.args]
        return Type(kind="con", name=resolver.fqn_with_package(name.package_id, name.module, name.name), args=args)
    if which == "syn":
        name = resolver.resolve_type_con(typ.syn.tysyn)
        args = [_lower_type_lf1(a, resolver) for a in typ.syn.args]
        return Type(kind="syn", name=resolver.fqn_with_package(name.package_id, name.module, name.name), args=args)
    if which == "prim":
        prim = typ.prim.prim
        args = [_lower_type_lf1(a, resolver) for a in typ.prim.args]
        if prim == daml_lf1_pb2.LIST:
            return Type(kind="list", args=args)
        if prim == daml_lf1_pb2.OPTIONAL:
            return Type(kind="optional", args=args)
        if prim == daml_lf1_pb2.PARTY:
            return Type(kind="con", name="Party")
        return Type(kind="con", name=daml_lf1_pb2.PrimType.Name(prim), args=args)
    if which == "struct":
        return Type(kind="struct")
    if which == "forall":
        return Type(kind="forall")
    if which == "nat":
        return Type(kind="nat", name=str(typ.nat))
    return Type(kind="unknown")


def _lower_type_lf2(typ: daml_lf2_pb2.Type, resolver: Lf2Resolver) -> Type:
    if typ is None:
        return Type(kind="unknown")
    which = typ.WhichOneof("Sum")
    if which == "interned_type":
        idx = typ.interned_type
        if 0 <= idx < len(resolver.interned.types):
            return _lower_type_lf2(resolver.interned.types[idx], resolver)
        return Type(kind="unknown")
    if which == "var":
        name = resolver.resolve_identifier(typ.var.var_interned_str)
        args = [_lower_type_lf2(a, resolver) for a in typ.var.args]
        return Type(kind="var", name=name, args=args)
    if which == "con":
        name = resolver.resolve_type_con(typ.con.tycon)
        args = [_lower_type_lf2(a, resolver) for a in typ.con.args]
        return Type(kind="con", name=resolver.fqn_with_package(name.package_id, name.module, name.name), args=args)
    if which == "syn":
        name = resolver.resolve_type_con(typ.syn.tysyn)
        args = [_lower_type_lf2(a, resolver) for a in typ.syn.args]
        return Type(kind="syn", name=resolver.fqn_with_package(name.package_id, name.module, name.name), args=args)
    if which == "builtin":
        builtin = typ.builtin.builtin
        args = [_lower_type_lf2(a, resolver) for a in typ.builtin.args]
        if builtin == daml_lf2_pb2.LIST:
            return Type(kind="list", args=args)
        if builtin == daml_lf2_pb2.OPTIONAL:
            return Type(kind="optional", args=args)
        if builtin == daml_lf2_pb2.PARTY:
            return Type(kind="con", name="Party")
        return Type(kind="con", name=daml_lf2_pb2.BuiltinType.Name(builtin), args=args)
    if which == "tapp":
        lhs = _lower_type_lf2(typ.tapp.lhs, resolver)
        rhs = _lower_type_lf2(typ.tapp.rhs, resolver)
        return Type(kind="app", args=[lhs, rhs])
    if which == "struct":
        return Type(kind="struct")
    if which == "forall":
        return Type(kind="forall")
    if which == "nat":
        return Type(kind="nat", name=str(typ.nat))
    return Type(kind="unknown")


def _lower_expr_lf1(
    expr: daml_lf1_pb2.Expr,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> Expr:
    location = _lower_location_lf1(expr.location, resolver, module_name, "expr") if expr.HasField("location") else None
    which = expr.WhichOneof("Sum")

    if which in ("var_str", "var_interned_str"):
        name = resolver.resolve_identifier(
            expr.var_str if which == "var_str" else None,
            expr.var_interned_str if which == "var_interned_str" else None,
        )
        return Expr(kind="var", value=name, typ=env.get(name), location=location)
    if which == "val":
        val = resolver.resolve_val_name(expr.val)
        return Expr(kind="val_ref", value=resolver.fqn_with_package(val.package_id, val.module, val.name), location=location)
    if which == "builtin":
        return Expr(kind="builtin", value=daml_lf1_pb2.BuiltinFunction.Name(expr.builtin), location=location)
    if which == "prim_con":
        return Expr(kind="prim_con", value=daml_lf1_pb2.PrimCon.Name(expr.prim_con), location=location)
    if which == "prim_lit":
        return _lower_prim_lit_lf1(expr.prim_lit, resolver, location)
    if which == "rec_con":
        fields = [
            Expr(
                kind="field",
                value=_lf1_field_name(f, resolver),
                children=[_lower_expr_lf1(f.expr, resolver, env, module_name, package_id)],
            )
            for f in expr.rec_con.fields
        ]
        return Expr(kind="record", value=_lf1_typecon_name(expr.rec_con.tycon, resolver), children=fields, location=location)
    if which == "rec_proj":
        field = _lf1_field_name(expr.rec_proj, resolver)
        record = _lower_expr_lf1(expr.rec_proj.record, resolver, env, module_name, package_id)
        return Expr(kind="record_proj", value=field, children=[record], location=location)
    if which == "rec_upd":
        field = _lf1_field_name(expr.rec_upd, resolver)
        record = _lower_expr_lf1(expr.rec_upd.record, resolver, env, module_name, package_id)
        update = _lower_expr_lf1(expr.rec_upd.update, resolver, env, module_name, package_id)
        return Expr(kind="record_upd", value=field, children=[record, update], location=location)
    if which == "variant_con":
        name = _lf1_variant_name(expr.variant_con, resolver)
        arg = _lower_expr_lf1(expr.variant_con.variant_arg, resolver, env, module_name, package_id)
        return Expr(kind="variant", value=name, children=[arg], location=location)
    if which == "enum_con":
        name = resolver.resolve_type_con(expr.enum_con.tycon).fqn()
        ctor = _lf1_enum_ctor(expr.enum_con, resolver)
        return Expr(kind="enum", value=f"{name}.{ctor}", location=location)
    if which == "struct_con":
        fields = [
            Expr(
                kind="field",
                value=_lf1_struct_field_name(f, resolver),
                children=[_lower_expr_lf1(f.expr, resolver, env, module_name, package_id)],
            )
            for f in expr.struct_con.fields
        ]
        return Expr(kind="struct", children=fields, location=location)
    if which == "struct_proj":
        field = _lf1_struct_field_name(expr.struct_proj, resolver)
        struct = _lower_expr_lf1(expr.struct_proj.struct, resolver, env, module_name, package_id)
        return Expr(kind="struct_proj", value=field, children=[struct], location=location)
    if which == "struct_upd":
        field = _lf1_struct_field_name(expr.struct_upd, resolver)
        struct = _lower_expr_lf1(expr.struct_upd.struct, resolver, env, module_name, package_id)
        update = _lower_expr_lf1(expr.struct_upd.update, resolver, env, module_name, package_id)
        return Expr(kind="struct_upd", value=field, children=[struct, update], location=location)
    if which == "app":
        fun = _lower_expr_lf1(expr.app.fun, resolver, env, module_name, package_id)
        args = [_lower_expr_lf1(a, resolver, env, module_name, package_id) for a in expr.app.args]
        return Expr(kind="app", children=[fun, *args], location=location)
    if which == "ty_app":
        body = _lower_expr_lf1(expr.ty_app.expr, resolver, env, module_name, package_id)
        types = [_lower_type_lf1(t, resolver) for t in expr.ty_app.types]
        return Expr(kind="ty_app", value=types, children=[body], location=location)
    if which == "abs":
        params = list(expr.abs.param)
        body = _lower_expr_lf1(expr.abs.body, resolver, env, module_name, package_id)
        for param in reversed(params):
            name = _lower_var_with_type_name_lf1(param, resolver)
            typ = _lower_type_lf1(param.type, resolver)
            env = {**env, name: typ}
            body = Expr(kind="lam", value=name, children=[body], location=location)
        return body
    if which == "ty_abs":
        body = _lower_expr_lf1(expr.ty_abs.body, resolver, env, module_name, package_id)
        return Expr(kind="ty_abs", children=[body], location=location)
    if which == "case":
        scrut = _lower_expr_lf1(expr.case.scrut, resolver, env, module_name, package_id)
        alts = [
            _lower_expr_lf1(alt.body, resolver, env, module_name, package_id) for alt in expr.case.alts
        ]
        patterns = [_lower_case_alt_pattern_lf1(alt, resolver) for alt in expr.case.alts]
        return Expr(kind="case", value=patterns, children=[scrut, *alts], location=location)
    if which == "let":
        bindings = []
        env2 = dict(env)
        for b in expr.let.bindings:
            name = _lower_var_with_type_name_lf1(b.binder, resolver)
            typ = _lower_type_lf1(b.binder.type, resolver)
            bound = _lower_expr_lf1(b.bound, resolver, env2, module_name, package_id)
            env2[name] = typ
            bindings.append(Expr(kind="binding", value=name, children=[bound]))
        body = _lower_expr_lf1(expr.let.body, resolver, env2, module_name, package_id)
        return Expr(kind="let", children=[*bindings, body], location=location)
    if which == "nil":
        typ = _lower_type_lf1(expr.nil.type, resolver)
        return Expr(kind="list", children=[], typ=Type(kind="list", args=[typ]), location=location)
    if which == "cons":
        flattened = _flatten_list_lf1(expr.cons, resolver, env, module_name, package_id)
        if flattened is not None:
            return Expr(kind="list", children=flattened, location=location)
        head = [
            _lower_expr_lf1(e, resolver, env, module_name, package_id) for e in expr.cons.front
        ]
        tail = _lower_expr_lf1(expr.cons.tail, resolver, env, module_name, package_id)
        return Expr(kind="cons", children=[*head, tail], location=location)
    if which == "update":
        return _lower_update_lf1(expr.update, resolver, env, module_name, package_id, location)
    if which == "optional_none":
        typ = _lower_type_lf1(expr.optional_none.type, resolver)
        return Expr(kind="optional", children=[], typ=Type(kind="optional", args=[typ]), location=location)
    if which == "optional_some":
        child = _lower_expr_lf1(expr.optional_some.body, resolver, env, module_name, package_id)
        typ = _lower_type_lf1(expr.optional_some.type, resolver)
        return Expr(
            kind="optional",
            children=[child],
            typ=Type(kind="optional", args=[typ]),
            location=location,
        )
    if which == "scenario":
        return _lower_scenario_lf1(expr.scenario, resolver, env, module_name, package_id, location)
    if which == "to_any":
        typ = _lower_type_lf1(expr.to_any.type, resolver)
        body = _lower_expr_lf1(expr.to_any.expr, resolver, env, module_name, package_id)
        return Expr(kind="to_any", value=typ, children=[body], location=location)
    if which == "from_any":
        typ = _lower_type_lf1(expr.from_any.type, resolver)
        body = _lower_expr_lf1(expr.from_any.expr, resolver, env, module_name, package_id)
        return Expr(kind="from_any", value=typ, children=[body], location=location)
    if which == "type_rep":
        typ = _lower_type_lf1(expr.type_rep, resolver)
        return Expr(kind="type_rep", value=typ, location=location)
    if which == "to_any_exception":
        typ = _lower_type_lf1(expr.to_any_exception.type, resolver)
        body = _lower_expr_lf1(expr.to_any_exception.expr, resolver, env, module_name, package_id)
        return Expr(kind="to_any_exception", value=typ, children=[body], location=location)
    if which == "from_any_exception":
        typ = _lower_type_lf1(expr.from_any_exception.type, resolver)
        body = _lower_expr_lf1(expr.from_any_exception.expr, resolver, env, module_name, package_id)
        return Expr(kind="from_any_exception", value=typ, children=[body], location=location)
    if which == "throw":
        return_type = _lower_type_lf1(expr.throw.return_type, resolver)
        exc_type = _lower_type_lf1(expr.throw.exception_type, resolver)
        exc_expr = _lower_expr_lf1(expr.throw.exception_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="throw",
            value={"return_type": return_type, "exception_type": exc_type},
            children=[exc_expr],
            location=location,
        )
    if which == "to_interface":
        interface = _lf1_typecon_name(expr.to_interface.interface_type, resolver)
        template = _lf1_typecon_name(expr.to_interface.template_type, resolver)
        body = _lower_expr_lf1(expr.to_interface.template_expr, resolver, env, module_name, package_id)
        return Expr(kind="to_interface", value={"interface": interface, "template": template}, children=[body], location=location)
    if which == "from_interface":
        interface = _lf1_typecon_name(expr.from_interface.interface_type, resolver)
        template = _lf1_typecon_name(expr.from_interface.template_type, resolver)
        body = _lower_expr_lf1(expr.from_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(kind="from_interface", value={"interface": interface, "template": template}, children=[body], location=location)
    if which == "call_interface":
        interface = _lf1_typecon_name(expr.call_interface.interface_type, resolver)
        method = resolver.interned_str(expr.call_interface.method_interned_name)
        body = _lower_expr_lf1(expr.call_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(kind="call_interface", value={"interface": interface, "method": method}, children=[body], location=location)
    if which == "view_interface":
        interface = _lf1_typecon_name(expr.view_interface.interface, resolver)
        body = _lower_expr_lf1(expr.view_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="view_interface", value=interface, children=[body], location=location)
    if which == "signatory_interface":
        interface = _lf1_typecon_name(expr.signatory_interface.interface, resolver)
        body = _lower_expr_lf1(expr.signatory_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="signatory_interface", value=interface, children=[body], location=location)
    if which == "observer_interface":
        interface = _lf1_typecon_name(expr.observer_interface.interface, resolver)
        body = _lower_expr_lf1(expr.observer_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="observer_interface", value=interface, children=[body], location=location)
    if which == "unsafe_from_interface":
        interface = _lf1_typecon_name(expr.unsafe_from_interface.interface_type, resolver)
        template = _lf1_typecon_name(expr.unsafe_from_interface.template_type, resolver)
        cid = _lower_expr_lf1(expr.unsafe_from_interface.contract_id_expr, resolver, env, module_name, package_id)
        body = _lower_expr_lf1(expr.unsafe_from_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="unsafe_from_interface",
            value={"interface": interface, "template": template},
            children=[cid, body],
            location=location,
        )
    if which == "interface_template_type_rep":
        interface = _lf1_typecon_name(expr.interface_template_type_rep.interface, resolver)
        body = _lower_expr_lf1(expr.interface_template_type_rep.expr, resolver, env, module_name, package_id)
        return Expr(kind="interface_template_type_rep", value=interface, children=[body], location=location)
    if which == "to_required_interface":
        required = _lf1_typecon_name(expr.to_required_interface.required_interface, resolver)
        requiring = _lf1_typecon_name(expr.to_required_interface.requiring_interface, resolver)
        body = _lower_expr_lf1(expr.to_required_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="to_required_interface", value={"required": required, "requiring": requiring}, children=[body], location=location)
    if which == "from_required_interface":
        required = _lf1_typecon_name(expr.from_required_interface.required_interface, resolver)
        requiring = _lf1_typecon_name(expr.from_required_interface.requiring_interface, resolver)
        body = _lower_expr_lf1(expr.from_required_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="from_required_interface", value={"required": required, "requiring": requiring}, children=[body], location=location)
    if which == "unsafe_from_required_interface":
        required = _lf1_typecon_name(expr.unsafe_from_required_interface.required_interface, resolver)
        requiring = _lf1_typecon_name(expr.unsafe_from_required_interface.requiring_interface, resolver)
        cid = _lower_expr_lf1(expr.unsafe_from_required_interface.contract_id_expr, resolver, env, module_name, package_id)
        body = _lower_expr_lf1(expr.unsafe_from_required_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="unsafe_from_required_interface",
            value={"required": required, "requiring": requiring},
            children=[cid, body],
            location=location,
        )
    if which == "choice_controller":
        template = _lf1_typecon_name(expr.choice_controller.template, resolver)
        choice = resolver.interned_str(expr.choice_controller.choice_interned_str)
        contract = _lower_expr_lf1(expr.choice_controller.contract_expr, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(expr.choice_controller.choice_arg_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="choice_controller",
            value={"template": template, "choice": choice},
            children=[contract, arg],
            location=location,
        )
    if which == "choice_observer":
        template = _lf1_typecon_name(expr.choice_observer.template, resolver)
        choice = resolver.interned_str(expr.choice_observer.choice_interned_str)
        contract = _lower_expr_lf1(expr.choice_observer.contract_expr, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(expr.choice_observer.choice_arg_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="choice_observer",
            value={"template": template, "choice": choice},
            children=[contract, arg],
            location=location,
        )
    if which == "experimental":
        exp_type = _lower_type_lf1(expr.experimental.type, resolver)
        return Expr(kind="experimental", value={"name": expr.experimental.name, "type": exp_type}, location=location)
    if which == "interned_expr":
        idx = expr.interned_expr
        if 0 <= idx < len(resolver.interned.exprs):
            return _lower_expr_lf1(resolver.interned.exprs[idx], resolver, env, module_name, package_id)
    return Expr(kind=f"expr.{which or 'unknown'}", location=location)


def _lower_expr_lf2(
    expr: daml_lf2_pb2.Expr,
    resolver: Lf2Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> Expr:
    location = _lower_location_lf2(expr.location, resolver, module_name, "expr") if expr.HasField("location") else None
    which = expr.WhichOneof("Sum")

    if which in ("var_interned_str", "var_str"):
        if which == "var_str":
            name = expr.var_str
        else:
            name = resolver.resolve_identifier(expr.var_interned_str)
        return Expr(kind="var", value=name, typ=env.get(name), location=location)
    if which == "val":
        val = resolver.resolve_val_name(expr.val)
        return Expr(kind="val_ref", value=resolver.fqn_with_package(val.package_id, val.module, val.name), location=location)
    if which == "builtin":
        return Expr(kind="builtin", value=daml_lf2_pb2.BuiltinFunction.Name(expr.builtin), location=location)
    if which in ("builtin_con", "prim_con"):
        value = expr.builtin_con if which == "builtin_con" else expr.prim_con
        return Expr(kind="prim_con", value=daml_lf2_pb2.BuiltinCon.Name(value), location=location)
    if which in ("builtin_lit", "prim_lit"):
        lit = expr.builtin_lit if which == "builtin_lit" else expr.prim_lit
        return _lower_prim_lit_lf2(lit, resolver, location)
    if which == "rec_con":
        fields = [
            Expr(
                kind="field",
                value=_lf2_field_name(f.field, resolver),
                children=[_lower_expr_lf2(f.expr, resolver, env, module_name, package_id)],
            )
            for f in expr.rec_con.fields
        ]
        return Expr(kind="record", value=_lf2_typecon_name(expr.rec_con.tycon, resolver), children=fields, location=location)
    if which == "rec_proj":
        field = _lf2_field_name(expr.rec_proj.field, resolver)
        record = _lower_expr_lf2(expr.rec_proj.record, resolver, env, module_name, package_id)
        return Expr(kind="record_proj", value=field, children=[record], location=location)
    if which == "rec_upd":
        field = _lf2_field_name(expr.rec_upd.field, resolver)
        record = _lower_expr_lf2(expr.rec_upd.record, resolver, env, module_name, package_id)
        update = _lower_expr_lf2(expr.rec_upd.update, resolver, env, module_name, package_id)
        return Expr(kind="record_upd", value=field, children=[record, update], location=location)
    if which == "variant_con":
        name = _lf2_variant_name(expr.variant_con, resolver)
        arg = _lower_expr_lf2(expr.variant_con.variant_arg, resolver, env, module_name, package_id)
        return Expr(kind="variant", value=name, children=[arg], location=location)
    if which == "enum_con":
        name = resolver.resolve_type_con(expr.enum_con.tycon).fqn()
        ctor = resolver.interned_str(expr.enum_con.enum_con_interned_str)
        return Expr(kind="enum", value=f"{name}.{ctor}", location=location)
    if which == "struct_con":
        fields = [
            Expr(
                kind="field",
                value=_lf2_struct_field_name(f.field, resolver),
                children=[_lower_expr_lf2(f.expr, resolver, env, module_name, package_id)],
            )
            for f in expr.struct_con.fields
        ]
        return Expr(kind="struct", children=fields, location=location)
    if which == "struct_proj":
        field = _lf2_struct_field_name(expr.struct_proj.field, resolver)
        struct = _lower_expr_lf2(expr.struct_proj.struct, resolver, env, module_name, package_id)
        return Expr(kind="struct_proj", value=field, children=[struct], location=location)
    if which == "struct_upd":
        field = _lf2_struct_field_name(expr.struct_upd.field, resolver)
        struct = _lower_expr_lf2(expr.struct_upd.struct, resolver, env, module_name, package_id)
        update = _lower_expr_lf2(expr.struct_upd.update, resolver, env, module_name, package_id)
        return Expr(kind="struct_upd", value=field, children=[struct, update], location=location)
    if which == "app":
        fun = _lower_expr_lf2(expr.app.fun, resolver, env, module_name, package_id)
        args = [_lower_expr_lf2(a, resolver, env, module_name, package_id) for a in expr.app.args]
        return Expr(kind="app", children=[fun, *args], location=location)
    if which == "ty_app":
        body = _lower_expr_lf2(expr.ty_app.expr, resolver, env, module_name, package_id)
        types = [_lower_type_lf2(t, resolver) for t in expr.ty_app.types]
        return Expr(kind="ty_app", value=types, children=[body], location=location)
    if which == "abs":
        params = list(expr.abs.param)
        body = _lower_expr_lf2(expr.abs.body, resolver, env, module_name, package_id)
        for param in reversed(params):
            name = resolver.resolve_identifier(param.var_interned_str)
            typ = _lower_type_lf2(param.type, resolver)
            env = {**env, name: typ}
            body = Expr(kind="lam", value=name, children=[body], location=location)
        return body
    if which == "ty_abs":
        body = _lower_expr_lf2(expr.ty_abs.body, resolver, env, module_name, package_id)
        return Expr(kind="ty_abs", children=[body], location=location)
    if which == "case":
        scrut = _lower_expr_lf2(expr.case.scrut, resolver, env, module_name, package_id)
        alts = [
            _lower_expr_lf2(alt.body, resolver, env, module_name, package_id) for alt in expr.case.alts
        ]
        patterns = [_lower_case_alt_pattern_lf2(alt, resolver) for alt in expr.case.alts]
        return Expr(kind="case", value=patterns, children=[scrut, *alts], location=location)
    if which == "let":
        bindings = []
        env2 = dict(env)
        for b in expr.let.bindings:
            name = resolver.resolve_identifier(b.binder.var_interned_str)
            typ = _lower_type_lf2(b.binder.type, resolver)
            bound = _lower_expr_lf2(b.bound, resolver, env2, module_name, package_id)
            env2[name] = typ
            bindings.append(Expr(kind="binding", value=name, children=[bound]))
        body = _lower_expr_lf2(expr.let.body, resolver, env2, module_name, package_id)
        return Expr(kind="let", children=[*bindings, body], location=location)
    if which == "nil":
        typ = _lower_type_lf2(expr.nil.type, resolver)
        return Expr(kind="list", children=[], typ=Type(kind="list", args=[typ]), location=location)
    if which == "cons":
        flattened = _flatten_list_lf2(expr.cons, resolver, env, module_name, package_id)
        if flattened is not None:
            return Expr(kind="list", children=flattened, location=location)
        head = [
            _lower_expr_lf2(e, resolver, env, module_name, package_id) for e in expr.cons.front
        ]
        tail = _lower_expr_lf2(expr.cons.tail, resolver, env, module_name, package_id)
        return Expr(kind="cons", children=[*head, tail], location=location)
    if which == "update":
        return _lower_update_lf2(expr.update, resolver, env, module_name, package_id, location)
    if which == "optional_none":
        typ = _lower_type_lf2(expr.optional_none.type, resolver)
        return Expr(kind="optional", children=[], typ=Type(kind="optional", args=[typ]), location=location)
    if which == "optional_some":
        child = _lower_expr_lf2(expr.optional_some.value, resolver, env, module_name, package_id)
        typ = _lower_type_lf2(expr.optional_some.type, resolver)
        return Expr(
            kind="optional",
            children=[child],
            typ=Type(kind="optional", args=[typ]),
            location=location,
        )
    if which == "to_any":
        typ = _lower_type_lf2(expr.to_any.type, resolver)
        body = _lower_expr_lf2(expr.to_any.expr, resolver, env, module_name, package_id)
        return Expr(kind="to_any", value=typ, children=[body], location=location)
    if which == "from_any":
        typ = _lower_type_lf2(expr.from_any.type, resolver)
        body = _lower_expr_lf2(expr.from_any.expr, resolver, env, module_name, package_id)
        return Expr(kind="from_any", value=typ, children=[body], location=location)
    if which == "type_rep":
        typ = _lower_type_lf2(expr.type_rep, resolver)
        return Expr(kind="type_rep", value=typ, location=location)
    if which == "to_any_exception":
        typ = _lower_type_lf2(expr.to_any_exception.type, resolver)
        body = _lower_expr_lf2(expr.to_any_exception.expr, resolver, env, module_name, package_id)
        return Expr(kind="to_any_exception", value=typ, children=[body], location=location)
    if which == "from_any_exception":
        typ = _lower_type_lf2(expr.from_any_exception.type, resolver)
        body = _lower_expr_lf2(expr.from_any_exception.expr, resolver, env, module_name, package_id)
        return Expr(kind="from_any_exception", value=typ, children=[body], location=location)
    if which == "throw":
        return_type = _lower_type_lf2(expr.throw.return_type, resolver)
        exc_type = _lower_type_lf2(expr.throw.exception_type, resolver)
        exc_expr = _lower_expr_lf2(expr.throw.exception_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="throw",
            value={"return_type": return_type, "exception_type": exc_type},
            children=[exc_expr],
            location=location,
        )
    if which == "to_interface":
        interface = _lf2_typecon_name(expr.to_interface.interface_type, resolver)
        template = _lf2_typecon_name(expr.to_interface.template_type, resolver)
        body = _lower_expr_lf2(expr.to_interface.template_expr, resolver, env, module_name, package_id)
        return Expr(kind="to_interface", value={"interface": interface, "template": template}, children=[body], location=location)
    if which == "from_interface":
        interface = _lf2_typecon_name(expr.from_interface.interface_type, resolver)
        template = _lf2_typecon_name(expr.from_interface.template_type, resolver)
        body = _lower_expr_lf2(expr.from_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(kind="from_interface", value={"interface": interface, "template": template}, children=[body], location=location)
    if which == "call_interface":
        interface = _lf2_typecon_name(expr.call_interface.interface_type, resolver)
        method = resolver.interned_str(expr.call_interface.method_interned_name)
        body = _lower_expr_lf2(expr.call_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(kind="call_interface", value={"interface": interface, "method": method}, children=[body], location=location)
    if which == "view_interface":
        interface = _lf2_typecon_name(expr.view_interface.interface, resolver)
        body = _lower_expr_lf2(expr.view_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="view_interface", value=interface, children=[body], location=location)
    if which == "signatory_interface":
        interface = _lf2_typecon_name(expr.signatory_interface.interface, resolver)
        body = _lower_expr_lf2(expr.signatory_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="signatory_interface", value=interface, children=[body], location=location)
    if which == "observer_interface":
        interface = _lf2_typecon_name(expr.observer_interface.interface, resolver)
        body = _lower_expr_lf2(expr.observer_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="observer_interface", value=interface, children=[body], location=location)
    if which == "unsafe_from_interface":
        interface = _lf2_typecon_name(expr.unsafe_from_interface.interface_type, resolver)
        template = _lf2_typecon_name(expr.unsafe_from_interface.template_type, resolver)
        cid = _lower_expr_lf2(expr.unsafe_from_interface.contract_id_expr, resolver, env, module_name, package_id)
        body = _lower_expr_lf2(expr.unsafe_from_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="unsafe_from_interface",
            value={"interface": interface, "template": template},
            children=[cid, body],
            location=location,
        )
    if which == "interface_template_type_rep":
        interface = _lf2_typecon_name(expr.interface_template_type_rep.interface, resolver)
        body = _lower_expr_lf2(expr.interface_template_type_rep.expr, resolver, env, module_name, package_id)
        return Expr(kind="interface_template_type_rep", value=interface, children=[body], location=location)
    if which == "to_required_interface":
        required = _lf2_typecon_name(expr.to_required_interface.required_interface, resolver)
        requiring = _lf2_typecon_name(expr.to_required_interface.requiring_interface, resolver)
        body = _lower_expr_lf2(expr.to_required_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="to_required_interface", value={"required": required, "requiring": requiring}, children=[body], location=location)
    if which == "from_required_interface":
        required = _lf2_typecon_name(expr.from_required_interface.required_interface, resolver)
        requiring = _lf2_typecon_name(expr.from_required_interface.requiring_interface, resolver)
        body = _lower_expr_lf2(expr.from_required_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="from_required_interface", value={"required": required, "requiring": requiring}, children=[body], location=location)
    if which == "unsafe_from_required_interface":
        required = _lf2_typecon_name(expr.unsafe_from_required_interface.required_interface, resolver)
        requiring = _lf2_typecon_name(expr.unsafe_from_required_interface.requiring_interface, resolver)
        cid = _lower_expr_lf2(expr.unsafe_from_required_interface.contract_id_expr, resolver, env, module_name, package_id)
        body = _lower_expr_lf2(expr.unsafe_from_required_interface.interface_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="unsafe_from_required_interface",
            value={"required": required, "requiring": requiring},
            children=[cid, body],
            location=location,
        )
    if which == "choice_controller":
        template = _lf2_typecon_name(expr.choice_controller.template, resolver)
        choice = resolver.resolve_identifier(expr.choice_controller.choice_interned_str)
        contract = _lower_expr_lf2(expr.choice_controller.contract_expr, resolver, env, module_name, package_id)
        arg = _lower_expr_lf2(expr.choice_controller.choice_arg_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="choice_controller",
            value={"template": template, "choice": choice},
            children=[contract, arg],
            location=location,
        )
    if which == "choice_observer":
        template = _lf2_typecon_name(expr.choice_observer.template, resolver)
        choice = resolver.resolve_identifier(expr.choice_observer.choice_interned_str)
        contract = _lower_expr_lf2(expr.choice_observer.contract_expr, resolver, env, module_name, package_id)
        arg = _lower_expr_lf2(expr.choice_observer.choice_arg_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="choice_observer",
            value={"template": template, "choice": choice},
            children=[contract, arg],
            location=location,
        )
    if which == "experimental":
        exp_type = _lower_type_lf2(expr.experimental.type, resolver)
        return Expr(kind="experimental", value={"name": expr.experimental.name, "type": exp_type}, location=location)
    if which == "interned_expr":
        idx = expr.interned_expr
        if 0 <= idx < len(resolver.interned.exprs):
            return _lower_expr_lf2(resolver.interned.exprs[idx], resolver, env, module_name, package_id)
    return Expr(kind=f"expr.{which or 'unknown'}", location=location)


def _lower_update_lf1(
    update: daml_lf1_pb2.Update,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
    location: Location | None,
) -> Expr:
    which = update.WhichOneof("Sum")
    if which == "pure":
        return Expr(
            kind="update.pure",
            children=[_lower_expr_lf1(update.pure.expr, resolver, env, module_name, package_id)],
            location=location,
        )
    if which == "block":
        bindings = []
        env2 = dict(env)
        for b in update.block.bindings:
            name = _lower_var_with_type_name_lf1(b.binder, resolver)
            typ = _lower_type_lf1(b.binder.type, resolver)
            bound = _lower_expr_lf1(b.bound, resolver, env2, module_name, package_id)
            env2[name] = typ
            bindings.append(Expr(kind="binding", value=name, children=[bound]))
        body = _lower_expr_lf1(update.block.body, resolver, env2, module_name, package_id)
        return Expr(kind="update.block", children=[*bindings, body], location=location)
    if which == "create":
        name = _lf1_typecon_name(update.create.template, resolver)
        body = _lower_expr_lf1(update.create.expr, resolver, env, module_name, package_id)
        return Expr(kind="update.create", value=name, children=[body], location=location)
    if which == "exercise":
        tmpl = _lf1_typecon_name(update.exercise.template, resolver)
        choice = _lf1_choice_name(update.exercise, resolver)
        cid = _lower_expr_lf1(update.exercise.cid, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(update.exercise.arg, resolver, env, module_name, package_id)
        return Expr(
            kind="update.exercise",
            value={"template": tmpl, "choice": choice},
            children=[cid, arg],
            location=location,
        )
    if which == "exercise_by_key":
        tmpl = _lf1_typecon_name(update.exercise_by_key.template, resolver)
        choice = _lf1_choice_name(update.exercise_by_key, resolver)
        key = _lower_expr_lf1(update.exercise_by_key.key, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(update.exercise_by_key.arg, resolver, env, module_name, package_id)
        return Expr(
            kind="update.exercise_by_key",
            value={"template": tmpl, "choice": choice},
            children=[key, arg],
            location=location,
        )
    if which == "fetch":
        tmpl = _lf1_typecon_name(update.fetch.template, resolver)
        cid = _lower_expr_lf1(update.fetch.cid, resolver, env, module_name, package_id)
        return Expr(kind="update.fetch", value=tmpl, children=[cid], location=location)
    if which == "create_interface":
        interface = _lf1_typecon_name(update.create_interface.interface, resolver)
        body = _lower_expr_lf1(update.create_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="update.create_interface", value=interface, children=[body], location=location)
    if which == "exercise_interface":
        interface = _lf1_typecon_name(update.exercise_interface.interface, resolver)
        choice = resolver.interned_str(update.exercise_interface.choice_interned_str)
        cid = _lower_expr_lf1(update.exercise_interface.cid, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(update.exercise_interface.arg, resolver, env, module_name, package_id)
        children = [cid, arg]
        if update.exercise_interface.HasField("guard"):
            guard = _lower_expr_lf1(update.exercise_interface.guard, resolver, env, module_name, package_id)
            children.append(guard)
        return Expr(
            kind="update.exercise_interface",
            value={"template": interface, "choice": choice},
            children=children,
            location=location,
        )
    if which == "fetch_interface":
        interface = _lf1_typecon_name(update.fetch_interface.interface, resolver)
        cid = _lower_expr_lf1(update.fetch_interface.cid, resolver, env, module_name, package_id)
        return Expr(kind="update.fetch_interface", value=interface, children=[cid], location=location)
    if which == "get_time":
        return Expr(kind="update.get_time", location=location)
    if which == "lookup_by_key":
        tmpl = _lf1_typecon_name(update.lookup_by_key.template, resolver)
        key = _lower_expr_lf1(update.lookup_by_key.key, resolver, env, module_name, package_id)
        return Expr(kind="update.lookup_by_key", value=tmpl, children=[key], location=location)
    if which == "fetch_by_key":
        tmpl = _lf1_typecon_name(update.fetch_by_key.template, resolver)
        key = _lower_expr_lf1(update.fetch_by_key.key, resolver, env, module_name, package_id)
        return Expr(kind="update.fetch_by_key", value=tmpl, children=[key], location=location)
    if which == "embed_expr":
        typ = _lower_type_lf1(update.embed_expr.type, resolver)
        body = _lower_expr_lf1(update.embed_expr.body, resolver, env, module_name, package_id)
        return Expr(kind="update.embed_expr", value=typ, children=[body], location=location)
    if which == "try_catch":
        return_type = _lower_type_lf1(update.try_catch.return_type, resolver)
        var = resolver.interned_str(update.try_catch.var_interned_str)
        try_expr = _lower_expr_lf1(update.try_catch.try_expr, resolver, env, module_name, package_id)
        catch_expr = _lower_expr_lf1(update.try_catch.catch_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="update.try_catch",
            value={"return_type": return_type, "var": var},
            children=[try_expr, catch_expr],
            location=location,
        )
    if which == "dynamic_exercise":
        tmpl = _lf1_typecon_name(update.dynamic_exercise.template, resolver)
        choice = resolver.interned_str(update.dynamic_exercise.choice_interned_str)
        cid = _lower_expr_lf1(update.dynamic_exercise.cid, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(update.dynamic_exercise.arg, resolver, env, module_name, package_id)
        return Expr(
            kind="update.dynamic_exercise",
            value={"template": tmpl, "choice": choice},
            children=[cid, arg],
            location=location,
        )
    if which == "soft_fetch":
        tmpl = _lf1_typecon_name(update.soft_fetch.template, resolver)
        cid = _lower_expr_lf1(update.soft_fetch.cid, resolver, env, module_name, package_id)
        return Expr(kind="update.soft_fetch", value=tmpl, children=[cid], location=location)
    if which == "soft_exercise":
        tmpl = _lf1_typecon_name(update.soft_exercise.template, resolver)
        choice = _lf1_choice_name(update.soft_exercise, resolver)
        cid = _lower_expr_lf1(update.soft_exercise.cid, resolver, env, module_name, package_id)
        arg = _lower_expr_lf1(update.soft_exercise.arg, resolver, env, module_name, package_id)
        return Expr(
            kind="update.soft_exercise",
            value={"template": tmpl, "choice": choice},
            children=[cid, arg],
            location=location,
        )
    return Expr(kind=f"update.{which or 'unknown'}", location=location)


def _lower_update_lf2(
    update: daml_lf2_pb2.Update,
    resolver: Lf2Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
    location: Location | None,
) -> Expr:
    which = update.WhichOneof("Sum")
    if which == "pure":
        return Expr(
            kind="update.pure",
            children=[_lower_expr_lf2(update.pure.expr, resolver, env, module_name, package_id)],
            location=location,
        )
    if which == "block":
        bindings = []
        env2 = dict(env)
        for b in update.block.bindings:
            name = resolver.resolve_identifier(b.binder.var_interned_str)
            typ = _lower_type_lf2(b.binder.type, resolver)
            bound = _lower_expr_lf2(b.bound, resolver, env2, module_name, package_id)
            env2[name] = typ
            bindings.append(Expr(kind="binding", value=name, children=[bound]))
        body = _lower_expr_lf2(update.block.body, resolver, env2, module_name, package_id)
        return Expr(kind="update.block", children=[*bindings, body], location=location)
    if which == "create":
        name = _lf2_typecon_name(update.create.template, resolver)
        body = _lower_expr_lf2(update.create.expr, resolver, env, module_name, package_id)
        return Expr(kind="update.create", value=name, children=[body], location=location)
    if which == "exercise":
        tmpl = _lf2_typecon_name(update.exercise.template, resolver)
        choice = resolver.resolve_identifier(update.exercise.choice_interned_str)
        cid = _lower_expr_lf2(update.exercise.cid, resolver, env, module_name, package_id)
        arg = _lower_expr_lf2(update.exercise.arg, resolver, env, module_name, package_id)
        return Expr(
            kind="update.exercise",
            value={"template": tmpl, "choice": choice},
            children=[cid, arg],
            location=location,
        )
    if which == "exercise_by_key":
        tmpl = _lf2_typecon_name(update.exercise_by_key.template, resolver)
        choice = resolver.resolve_identifier(update.exercise_by_key.choice_interned_str)
        key = _lower_expr_lf2(update.exercise_by_key.key, resolver, env, module_name, package_id)
        arg = _lower_expr_lf2(update.exercise_by_key.arg, resolver, env, module_name, package_id)
        return Expr(
            kind="update.exercise_by_key",
            value={"template": tmpl, "choice": choice},
            children=[key, arg],
            location=location,
        )
    if which == "fetch":
        tmpl = _lf2_typecon_name(update.fetch.template, resolver)
        cid = _lower_expr_lf2(update.fetch.cid, resolver, env, module_name, package_id)
        return Expr(kind="update.fetch", value=tmpl, children=[cid], location=location)
    if which == "create_interface":
        interface = _lf2_typecon_name(update.create_interface.interface, resolver)
        body = _lower_expr_lf2(update.create_interface.expr, resolver, env, module_name, package_id)
        return Expr(kind="update.create_interface", value=interface, children=[body], location=location)
    if which == "exercise_interface":
        interface = _lf2_typecon_name(update.exercise_interface.interface, resolver)
        choice = resolver.resolve_identifier(update.exercise_interface.choice_interned_str)
        cid = _lower_expr_lf2(update.exercise_interface.cid, resolver, env, module_name, package_id)
        arg = _lower_expr_lf2(update.exercise_interface.arg, resolver, env, module_name, package_id)
        children = [cid, arg]
        if update.exercise_interface.HasField("guard"):
            guard = _lower_expr_lf2(update.exercise_interface.guard, resolver, env, module_name, package_id)
            children.append(guard)
        return Expr(
            kind="update.exercise_interface",
            value={"template": interface, "choice": choice},
            children=children,
            location=location,
        )
    if which == "fetch_interface":
        interface = _lf2_typecon_name(update.fetch_interface.interface, resolver)
        cid = _lower_expr_lf2(update.fetch_interface.cid, resolver, env, module_name, package_id)
        return Expr(kind="update.fetch_interface", value=interface, children=[cid], location=location)
    if which == "get_time":
        return Expr(kind="update.get_time", location=location)
    if which == "lookup_by_key":
        tmpl = _lf2_typecon_name(update.lookup_by_key.template, resolver)
        return Expr(kind="update.lookup_by_key", value=tmpl, location=location)
    if which == "fetch_by_key":
        tmpl = _lf2_typecon_name(update.fetch_by_key.template, resolver)
        return Expr(kind="update.fetch_by_key", value=tmpl, location=location)
    if which == "embed_expr":
        typ = _lower_type_lf2(update.embed_expr.type, resolver)
        body = _lower_expr_lf2(update.embed_expr.body, resolver, env, module_name, package_id)
        return Expr(kind="update.embed_expr", value=typ, children=[body], location=location)
    if which == "try_catch":
        return_type = _lower_type_lf2(update.try_catch.return_type, resolver)
        var = resolver.resolve_identifier(update.try_catch.var_interned_str)
        try_expr = _lower_expr_lf2(update.try_catch.try_expr, resolver, env, module_name, package_id)
        catch_expr = _lower_expr_lf2(update.try_catch.catch_expr, resolver, env, module_name, package_id)
        return Expr(
            kind="update.try_catch",
            value={"return_type": return_type, "var": var},
            children=[try_expr, catch_expr],
            location=location,
        )
    if which == "ledger_time_lt":
        bound = _lower_expr_lf2(update.ledger_time_lt, resolver, env, module_name, package_id)
        return Expr(kind="update.ledger_time_lt", children=[bound], location=location)
    return Expr(kind=f"update.{which or 'unknown'}", location=location)


# --- Scenario (LF1 only) ---


def _lower_scenario_lf1(
    scenario: daml_lf1_pb2.Scenario,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
    location: Location | None,
) -> Expr:
    which = scenario.WhichOneof("Sum")
    if which == "pure":
        typ = _lower_type_lf1(scenario.pure.type, resolver)
        body = _lower_expr_lf1(scenario.pure.expr, resolver, env, module_name, package_id)
        return Expr(kind="scenario.pure", value=typ, children=[body], location=location)
    if which == "block":
        bindings = []
        env2 = dict(env)
        for b in scenario.block.bindings:
            name = _lower_var_with_type_name_lf1(b.binder, resolver)
            typ = _lower_type_lf1(b.binder.type, resolver)
            bound = _lower_expr_lf1(b.bound, resolver, env2, module_name, package_id)
            env2[name] = typ
            bindings.append(Expr(kind="binding", value=name, children=[bound]))
        body = _lower_expr_lf1(scenario.block.body, resolver, env2, module_name, package_id)
        return Expr(kind="scenario.block", children=[*bindings, body], location=location)
    if which in ("commit", "mustFailAt"):
        commit = scenario.commit if which == "commit" else scenario.mustFailAt
        party = _lower_expr_lf1(commit.party, resolver, env, module_name, package_id)
        expr = _lower_expr_lf1(commit.expr, resolver, env, module_name, package_id)
        ret_type = _lower_type_lf1(commit.ret_type, resolver)
        return Expr(
            kind=f"scenario.{which}",
            value={"return_type": ret_type},
            children=[party, expr],
            location=location,
        )
    if which == "pass":
        pass_expr = getattr(scenario, "pass", None)
        if pass_expr is None:
            pass_expr = scenario.pass_
        body = _lower_expr_lf1(pass_expr, resolver, env, module_name, package_id)
        return Expr(kind="scenario.pass", children=[body], location=location)
    if which == "get_time":
        return Expr(kind="scenario.get_time", location=location)
    if which == "get_party":
        body = _lower_expr_lf1(scenario.get_party, resolver, env, module_name, package_id)
        return Expr(kind="scenario.get_party", children=[body], location=location)
    if which == "embed_expr":
        typ = _lower_type_lf1(scenario.embed_expr.type, resolver)
        body = _lower_expr_lf1(scenario.embed_expr.body, resolver, env, module_name, package_id)
        return Expr(kind="scenario.embed_expr", value=typ, children=[body], location=location)
    return Expr(kind=f"scenario.{which or 'unknown'}", location=location)


# --- Case pattern helpers ---


def _lower_case_alt_pattern_lf1(alt: daml_lf1_pb2.CaseAlt, resolver: Lf1Resolver) -> dict[str, Any]:
    which = alt.WhichOneof("Sum")
    if which == "default":
        return {"kind": "default"}
    if which == "variant":
        con = _lf1_typecon_name(alt.variant.con, resolver)
        var_which = alt.variant.WhichOneof("variant")
        if var_which == "variant_str":
            variant = alt.variant.variant_str
        else:
            variant = resolver.interned_str(alt.variant.variant_interned_str)
        binder = None
        binder_which = alt.variant.WhichOneof("binder")
        if binder_which == "binder_str":
            binder = alt.variant.binder_str
        elif binder_which == "binder_interned_str":
            binder = resolver.interned_str(alt.variant.binder_interned_str)
        return {"kind": "variant", "type": con, "variant": variant, "binder": binder}
    if which == "prim_con":
        return {"kind": "prim_con", "value": daml_lf1_pb2.PrimCon.Name(alt.prim_con)}
    if which == "nil":
        return {"kind": "nil"}
    if which == "cons":
        head = None
        tail = None
        head_which = alt.cons.WhichOneof("var_head")
        if head_which == "var_head_str":
            head = alt.cons.var_head_str
        elif head_which == "var_head_interned_str":
            head = resolver.interned_str(alt.cons.var_head_interned_str)
        tail_which = alt.cons.WhichOneof("var_tail")
        if tail_which == "var_tail_str":
            tail = alt.cons.var_tail_str
        elif tail_which == "var_tail_interned_str":
            tail = resolver.interned_str(alt.cons.var_tail_interned_str)
        return {"kind": "cons", "head": head, "tail": tail}
    if which == "optional_none":
        return {"kind": "optional_none"}
    if which == "optional_some":
        body = None
        body_which = alt.optional_some.WhichOneof("var_body")
        if body_which == "var_body_str":
            body = alt.optional_some.var_body_str
        elif body_which == "var_body_interned_str":
            body = resolver.interned_str(alt.optional_some.var_body_interned_str)
        return {"kind": "optional_some", "binder": body}
    if which == "enum":
        con = _lf1_typecon_name(alt.enum.con, resolver)
        ctor_which = alt.enum.WhichOneof("constructor")
        if ctor_which == "constructor_str":
            ctor = alt.enum.constructor_str
        else:
            ctor = resolver.interned_str(alt.enum.constructor_interned_str)
        return {"kind": "enum", "type": con, "constructor": ctor}
    return {"kind": which or "unknown"}


def _lower_case_alt_pattern_lf2(alt: daml_lf2_pb2.CaseAlt, resolver: Lf2Resolver) -> dict[str, Any]:
    which = alt.WhichOneof("Sum")
    if which == "default":
        return {"kind": "default"}
    if which == "variant":
        con = _lf2_typecon_name(alt.variant.con, resolver)
        variant = resolver.interned_str(alt.variant.variant_interned_str)
        binder = resolver.interned_str(alt.variant.binder_interned_str)
        return {"kind": "variant", "type": con, "variant": variant, "binder": binder}
    if which == "builtin_con":
        return {"kind": "builtin_con", "value": daml_lf2_pb2.BuiltinCon.Name(alt.builtin_con)}
    if which == "nil":
        return {"kind": "nil"}
    if which == "cons":
        head = resolver.interned_str(alt.cons.var_head_interned_str)
        tail = resolver.interned_str(alt.cons.var_tail_interned_str)
        return {"kind": "cons", "head": head, "tail": tail}
    if which == "optional_none":
        return {"kind": "optional_none"}
    if which == "optional_some":
        body = resolver.interned_str(alt.optional_some.var_body_interned_str)
        return {"kind": "optional_some", "binder": body}
    if which == "enum":
        con = _lf2_typecon_name(alt.enum.con, resolver)
        ctor = resolver.interned_str(alt.enum.constructor_interned_str)
        return {"kind": "enum", "type": con, "constructor": ctor}
    return {"kind": which or "unknown"}


# --- Name helpers ---


def _lf1_typecon_name(tycon: daml_lf1_pb2.TypeConName | daml_lf1_pb2.Type.Con, resolver: Lf1Resolver) -> str:
    if hasattr(tycon, "tycon"):
        tycon = tycon.tycon
    name = resolver.resolve_type_con(tycon)
    return resolver.fqn_with_package(name.package_id, name.module, name.name)


def _lf2_typecon_name(tycon: daml_lf2_pb2.TypeConId | daml_lf2_pb2.Type.Con, resolver: Lf2Resolver) -> str:
    if hasattr(tycon, "tycon"):
        tycon = tycon.tycon
    name = resolver.resolve_type_con(tycon)
    return resolver.fqn_with_package(name.package_id, name.module, name.name)


def _lf1_choice_name(ex: Any, resolver: Lf1Resolver) -> str:
    which = None
    try:
        which = ex.WhichOneof("choice")
    except ValueError:
        which = None
    if which == "choice_str":
        return ex.choice_str
    if which == "choice_interned_str":
        return resolver.interned_str(ex.choice_interned_str)
    if getattr(ex, "choice_str", ""):
        return ex.choice_str
    if hasattr(ex, "choice_interned_str"):
        return resolver.interned_str(ex.choice_interned_str)
    return "<choice>"


def _lf1_field_name(field_msg: Any, resolver: Lf1Resolver) -> str:
    which = field_msg.WhichOneof("field")
    if which == "field_str":
        return field_msg.field_str
    return resolver.interned_str(field_msg.field_interned_str)


def _lf2_field_name(field_msg: Any, resolver: Lf2Resolver) -> str:
    return resolver.interned_str(field_msg.field_interned_str)


def _lf1_struct_field_name(field_msg: Any, resolver: Lf1Resolver) -> str:
    which = field_msg.WhichOneof("field")
    if which == "field_str":
        return field_msg.field_str
    return resolver.interned_str(field_msg.field_interned_str)


def _lf2_struct_field_name(field_msg: Any, resolver: Lf2Resolver) -> str:
    return resolver.interned_str(field_msg.field_interned_str)


def _lf1_variant_name(variant: daml_lf1_pb2.Expr.VariantCon, resolver: Lf1Resolver) -> str:
    which = variant.WhichOneof("variant_con")
    if which == "variant_con_str":
        return variant.variant_con_str
    return resolver.interned_str(variant.variant_con_interned_str)


def _lf2_variant_name(variant: daml_lf2_pb2.Expr.VariantCon, resolver: Lf2Resolver) -> str:
    return resolver.interned_str(variant.variant_con_interned_str)


def _lf1_enum_ctor(enum_con: daml_lf1_pb2.Expr.EnumCon, resolver: Lf1Resolver) -> str:
    which = enum_con.WhichOneof("enum_con")
    if which == "enum_con_str":
        return enum_con.enum_con_str
    return resolver.interned_str(enum_con.enum_con_interned_str)


# --- Literals and list helpers ---


def _lower_prim_lit_lf1(lit: daml_lf1_pb2.PrimLit, resolver: Lf1Resolver, location: Location | None) -> Expr:
    which = lit.WhichOneof("Sum")
    if which == "party_str":
        return Expr(kind="party", value=lit.party_str, location=location)
    if which == "party_interned_str":
        return Expr(kind="party", value=resolver.interned_str(lit.party_interned_str), location=location)
    if which == "text_str":
        return Expr(kind="text", value=lit.text_str, location=location)
    if which == "text_interned_str":
        return Expr(kind="text", value=resolver.interned_str(lit.text_interned_str), location=location)
    if which == "decimal_str":
        return Expr(kind="decimal", value=lit.decimal_str, location=location)
    if which == "int64":
        return Expr(kind="int64", value=lit.int64, location=location)
    if which == "timestamp":
        return Expr(kind="timestamp", value=lit.timestamp, location=location)
    if which == "date":
        return Expr(kind="date", value=lit.date, location=location)
    if which == "numeric_interned_str":
        return Expr(kind="numeric", value=resolver.interned_str(lit.numeric_interned_str), location=location)
    if which == "rounding_mode":
        return Expr(
            kind="rounding_mode",
            value=daml_lf1_pb2.PrimLit.RoundingMode.Name(lit.rounding_mode),
            location=location,
        )
    return Expr(kind=f"lit.{which}", location=location)


def _lower_prim_lit_lf2(lit: daml_lf2_pb2.PrimLit, resolver: Lf2Resolver, location: Location | None) -> Expr:
    which = lit.WhichOneof("Sum")
    if which == "party_interned_str":
        return Expr(kind="party", value=resolver.interned_str(lit.party_interned_str), location=location)
    if which == "text_interned_str":
        return Expr(kind="text", value=resolver.interned_str(lit.text_interned_str), location=location)
    if which == "int64":
        return Expr(kind="int64", value=lit.int64, location=location)
    if which == "timestamp":
        return Expr(kind="timestamp", value=lit.timestamp, location=location)
    if which == "date":
        return Expr(kind="date", value=lit.date, location=location)
    if which == "numeric_interned_str":
        return Expr(kind="numeric", value=resolver.interned_str(lit.numeric_interned_str), location=location)
    if which == "failure_category":
        return Expr(
            kind="failure_category",
            value=daml_lf2_pb2.BuiltinLit.FailureCategory.Name(lit.failure_category),
            location=location,
        )
    if which == "rounding_mode":
        return Expr(
            kind="rounding_mode",
            value=daml_lf2_pb2.BuiltinLit.RoundingMode.Name(lit.rounding_mode),
            location=location,
        )
    return Expr(kind=f"lit.{which}", location=location)


def _flatten_list_lf1(
    cons: daml_lf1_pb2.Expr.Cons,
    resolver: Lf1Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> list[Expr] | None:
    items = [_lower_expr_lf1(e, resolver, env, module_name, package_id) for e in cons.front]
    tail_expr = cons.tail
    if tail_expr.WhichOneof("Sum") == "nil":
        return items
    if tail_expr.WhichOneof("Sum") == "cons":
        rest = _flatten_list_lf1(tail_expr.cons, resolver, env, module_name, package_id)
        if rest is None:
            return None
        return items + rest
    return None


def _flatten_list_lf2(
    cons: daml_lf2_pb2.Expr.Cons,
    resolver: Lf2Resolver,
    env: dict[str, Type],
    module_name: str,
    package_id: str,
) -> list[Expr] | None:
    items = [_lower_expr_lf2(e, resolver, env, module_name, package_id) for e in cons.front]
    tail_expr = cons.tail
    if tail_expr.WhichOneof("Sum") == "nil":
        return items
    if tail_expr.WhichOneof("Sum") == "cons":
        rest = _flatten_list_lf2(tail_expr.cons, resolver, env, module_name, package_id)
        if rest is None:
            return None
        return items + rest
    return None
