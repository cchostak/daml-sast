# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from google.protobuf.message import DecodeError

from daml_sast.lf.archive import DalfEntry
from daml_sast.lf.compat import LfVersion, is_supported, normalize_version
from daml_sast.lf.limits import limits
from daml_sast.lf.proto.com.digitalasset.daml.lf.archive import (
    daml_lf1_pb2,
    daml_lf2_pb2,
    daml_lf_pb2,
)


@dataclass(frozen=True)
class InternedTables:
    strings: list[str]
    dotted_names: list[str]
    types: list[Any]
    kinds: list[Any]
    exprs: list[Any]
    imports: list[str]


@dataclass(frozen=True)
class LfPackage:
    package_id: str
    name: str
    version: str
    lf_version: str
    lf_version_full: str
    lf_major: int
    lf_minor: int
    lf_patch: Optional[int]
    archive_payload: bytes
    package_bytes: bytes
    dalf_path: str
    lf_package: Any
    interned: InternedTables


class ProtoDecodeError(ValueError):
    pass


def decode_dalf(entry: DalfEntry) -> LfPackage:
    lim = limits()
    if len(entry.raw) > lim.max_dalf_bytes:
        raise ProtoDecodeError(
            f"Archive size {len(entry.raw)} exceeds max {lim.max_dalf_bytes} bytes"
        )
    try:
        archive = daml_lf_pb2.Archive()
        archive.ParseFromString(entry.raw)
    except (DecodeError, RecursionError) as exc:
        raise ProtoDecodeError(f"Archive decode failed: {exc}") from exc

    if archive.hash_function != daml_lf_pb2.SHA256:
        raise ProtoDecodeError("Unsupported hash function in archive")

    payload_bytes = archive.payload
    if not payload_bytes:
        raise ProtoDecodeError("Archive payload missing")
    if len(payload_bytes) > lim.max_archive_payload_bytes:
        raise ProtoDecodeError(
            f"Archive payload size {len(payload_bytes)} exceeds max "
            f"{lim.max_archive_payload_bytes} bytes"
        )

    if archive.hash:
        expected = _sha256_hex(payload_bytes)
        if expected != archive.hash:
            raise ProtoDecodeError("Archive payload hash mismatch")

    try:
        payload = daml_lf_pb2.ArchivePayload()
        payload.ParseFromString(payload_bytes)
    except (DecodeError, RecursionError) as exc:
        raise ProtoDecodeError(f"ArchivePayload decode failed: {exc}") from exc

    which = payload.WhichOneof("Sum")
    if which not in ("daml_lf_1", "daml_lf_2"):
        raise ProtoDecodeError("Unsupported ArchivePayload variant")

    lf_major = 1 if which == "daml_lf_1" else 2
    package_bytes = getattr(payload, which)
    if not package_bytes:
        raise ProtoDecodeError("ArchivePayload missing Daml-LF package bytes")
    if len(package_bytes) > lim.max_package_bytes:
        raise ProtoDecodeError(
            f"Package size {len(package_bytes)} exceeds max {lim.max_package_bytes} bytes"
        )

    try:
        version = normalize_version(lf_major, payload.minor, payload.patch)
    except ValueError as exc:
        raise ProtoDecodeError(str(exc)) from exc

    if lf_major == 1:
        try:
            lf_pkg = _decode_lf1_package(package_bytes)
        except ProtoDecodeError as exc:
            lf_pkg, version, lf_major = _decode_lf1_fallback_as_lf2(
                package_bytes, exc
            )
    else:
        lf_pkg = _decode_lf2_package(package_bytes)

    if not is_supported(version):
        raise ProtoDecodeError(f"Unsupported Daml-LF version: {version.short()}")

    _enforce_proto_limits(
        lf_pkg,
        max_depth=lim.max_proto_depth,
        max_nodes=lim.max_proto_nodes,
        label=f"LF{lf_major} package",
    )
    interned = _extract_interned_tables(lf_major, lf_pkg)
    name, ver = _extract_metadata(lf_major, lf_pkg, interned)

    return LfPackage(
        package_id=archive.hash or _sha256_hex(payload_bytes),
        name=name,
        version=ver,
        lf_version=version.short(),
        lf_version_full=version.full(),
        lf_major=version.major,
        lf_minor=version.minor,
        lf_patch=version.patch,
        archive_payload=payload_bytes,
        package_bytes=package_bytes,
        dalf_path=entry.path,
        lf_package=lf_pkg,
        interned=interned,
    )


def _decode_lf1_package(raw: bytes) -> daml_lf1_pb2.Package:
    try:
        pkg = daml_lf1_pb2.Package()
        pkg.ParseFromString(raw)
    except (DecodeError, RecursionError) as exc:
        raise ProtoDecodeError(f"LF1 Package decode failed: {exc}") from exc
    return pkg


def _decode_lf2_package(raw: bytes) -> daml_lf2_pb2.Package:
    try:
        pkg = daml_lf2_pb2.Package()
        pkg.ParseFromString(raw)
    except (DecodeError, RecursionError) as exc:
        raise ProtoDecodeError(f"LF2 Package decode failed: {exc}") from exc
    return pkg


def _extract_interned_tables(major: int, pkg: Any) -> InternedTables:
    strings = list(pkg.interned_strings)
    dotted_names = []
    for dotted in pkg.interned_dotted_names:
        segments = [strings[i] for i in dotted.segments_interned_str if i < len(strings)]
        dotted_names.append(".".join(segments))

    types = list(pkg.interned_types)
    kinds = list(getattr(pkg, "interned_kinds", []))
    exprs = list(getattr(pkg, "interned_exprs", []))

    imports: list[str] = []
    if major == 2:
        which = pkg.WhichOneof("ImportsSum")
        if which == "package_imports":
            imports = list(pkg.package_imports.imported_packages)

    return InternedTables(
        strings=strings,
        dotted_names=dotted_names,
        types=types,
        kinds=kinds,
        exprs=exprs,
        imports=imports,
    )


def _extract_metadata(major: int, pkg: Any, interned: InternedTables) -> tuple[str, str]:
    if not hasattr(pkg, "metadata"):
        return "", ""
    try:
        if not pkg.HasField("metadata"):
            return "", ""
    except ValueError:
        # Some proto versions may not allow HasField on scalar-only metadata
        pass

    name = ""
    version = ""
    idx = getattr(pkg.metadata, "name_interned_str", 0)
    if 0 <= idx < len(interned.strings):
        name = interned.strings[idx]
    idx = getattr(pkg.metadata, "version_interned_str", 0)
    if 0 <= idx < len(interned.strings):
        version = interned.strings[idx]
    return name, version


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _decode_lf1_fallback_as_lf2(
    raw: bytes, err: ProtoDecodeError
) -> tuple[daml_lf2_pb2.Package, LfVersion, int]:
    try:
        lf2_pkg = _decode_lf2_package(raw)
    except ProtoDecodeError:
        raise err

    interned = _extract_interned_tables(2, lf2_pkg)
    name, _ = _extract_metadata(2, lf2_pkg, interned)
    if name != "daml-prim":
        raise err

    version = normalize_version(2, "1", None)
    return lf2_pkg, version, 2


def _enforce_proto_limits(
    msg: Any, *, max_depth: int, max_nodes: int, label: str
) -> None:
    stack: list[tuple[Any, int]] = [(msg, 1)]
    seen = 0
    while stack:
        current, depth = stack.pop()
        seen += 1
        if seen > max_nodes:
            raise ProtoDecodeError(
                f"{label} exceeds max node count {max_nodes}"
            )
        if depth > max_depth:
            raise ProtoDecodeError(f"{label} exceeds max depth {max_depth}")
        for field, value in current.ListFields():
            if field.type != field.TYPE_MESSAGE:
                continue
            if field.label == field.LABEL_REPEATED:
                for item in value:
                    stack.append((item, depth + 1))
            else:
                stack.append((value, depth + 1))
