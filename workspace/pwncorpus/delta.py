"""Verifiable delta (incremental) packages between two publications.

An offline mirror should not have to re-download a full export for every
release. A delta package captures the difference between two published
versions so a mirror holding the base export can be advanced to the target
export locally:

  delta.json     binds the base AND target manifests (full manifests,
                 including their self-hashes) and declares the added /
                 changed / removed bucket files
  buckets/*.txt  only the added and changed bucket files

Applying a delta is atomic with respect to the mirror directory: every
fallible step (package integrity check, local-baseline check, staging the
new tree, verifying the staged tree) happens before the mirror is touched,
and the final commit is two renames. Any failure - baseline mismatch,
tampered or incomplete package, interrupted write - raises DeltaError with
a clear message and leaves the original mirror byte-for-byte intact, so it
still passes the plain export verifier. Re-applying an already-applied
delta is a no-op and never corrupts the mirror.

Usage:
  python -m pwncorpus.cli --db corpus.db delta --from-version 1 --to-version 2 --out delta-1-2
  python -m pwncorpus.verifier delta-check delta-1-2
  python -m pwncorpus.verifier delta-apply export-mirror delta-1-2
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile

from . import core, verifier

FORMAT = "pwncorpus-delta/1"

_MANIFEST_FIELDS = ("version", "hash_algo", "prefix_len", "threshold_k",
                    "created_at", "files")


class DeltaError(Exception):
    """A delta package or application problem. Messages must be actionable."""


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_hash(manifest: dict) -> str:
    payload = {f: manifest[f] for f in _MANIFEST_FIELDS}
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()


def _load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _diff_manifests(base_files: dict, target_files: dict):
    """Bucket-level diff: (added, changed, removed) with target hashes."""
    added = {p: target_files[p]
             for p in sorted(target_files.keys() - base_files.keys())}
    changed = {p: target_files[p]
               for p in sorted(base_files.keys() & target_files.keys())
               if base_files[p] != target_files[p]}
    removed = sorted(base_files.keys() - target_files.keys())
    return added, changed, removed


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _link_or_copy(src: str, dst: str) -> None:
    """Hard-link (cheap, same filesystem) with a copy fallback."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def build_delta(base_export: str, target_export: str, out_dir: str) -> dict:
    """Create a delta package advancing a mirror from base_export to
    target_export. Both directories must be valid full exports; they are
    verified before anything is written."""
    errors = verifier.verify_export(base_export)
    if errors:
        raise DeltaError(f"base export is invalid: {errors[0]}")
    errors = verifier.verify_export(target_export)
    if errors:
        raise DeltaError(f"target export is invalid: {errors[0]}")
    base = _load_json(os.path.join(base_export, "manifest.json"))
    target = _load_json(os.path.join(target_export, "manifest.json"))
    if (base["hash_algo"], base["prefix_len"]) != (target["hash_algo"],
                                                   target["prefix_len"]):
        raise DeltaError(
            "base and target use different hash_algo/prefix_len; a delta"
            " cannot span a bucketing change, ship a full export instead")
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        raise DeltaError(f"output directory is not empty: {out_dir}")

    added, changed, removed = _diff_manifests(base["files"], target["files"])
    payload = {
        "format": FORMAT,
        "base": base,
        "target": target,
        "added": added,
        "changed": changed,
        "removed": removed,
    }
    package = dict(payload)
    package["delta_sha256"] = hashlib.sha256(
        _canonical(payload).encode()).hexdigest()

    bdir = os.path.join(out_dir, "buckets")
    os.makedirs(bdir, exist_ok=True)
    for prefix in sorted(set(added) | set(changed)):
        shutil.copyfile(
            os.path.join(target_export, "buckets", f"{prefix}.txt"),
            os.path.join(bdir, f"{prefix}.txt"))
    with open(os.path.join(out_dir, "delta.json"), "w", encoding="utf-8") as fh:
        json.dump(package, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return package


def export_delta(conn, from_version: int, to_version: int, out_dir: str) -> dict:
    """Generate a delta package between two publications stored in the DB.
    Both versions are exported (with the usual self-check) to a scratch
    directory and diffed there, so the package is built from exactly the
    bytes a mirror would have downloaded."""
    tmp = tempfile.mkdtemp(prefix="pwncorpus-delta-")
    try:
        base_dir = os.path.join(tmp, "base")
        target_dir = os.path.join(tmp, "target")
        core.export_version(conn, from_version, base_dir)
        core.export_version(conn, to_version, target_dir)
        return build_delta(base_dir, target_dir, out_dir)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Integrity check (offline, no DB)
# --------------------------------------------------------------------------

def check_delta(delta_dir: str) -> list[str]:
    """Return a list of problems with the delta package; empty means valid.

    Verifies: the embedded base/target manifests are self-consistent, the
    declared added/changed/removed sets equal the diff of those manifests,
    the package self-hash matches, every needed bucket file is present and
    hashes to the target manifest's value, and there are no stray files.
    """
    errors: list[str] = []
    package = _load_json(os.path.join(delta_dir, "delta.json"))
    if package is None:
        return [f"missing or unreadable delta manifest: "
                f"{os.path.join(delta_dir, 'delta.json')}"]
    for field in ("format", "base", "target", "added", "changed", "removed",
                  "delta_sha256"):
        if field not in package:
            errors.append(f"delta manifest missing field: {field}")
    if errors:
        return errors
    if package["format"] != FORMAT:
        errors.append(f"unsupported delta format: {package['format']!r}")

    manifests = {}
    for role in ("base", "target"):
        m = package[role]
        if not isinstance(m, dict) or any(
                f not in m for f in _MANIFEST_FIELDS + ("manifest_sha256",)):
            errors.append(f"{role} manifest is incomplete")
            continue
        algo, plen = m["hash_algo"], m["prefix_len"]
        if (algo not in verifier.HASH_HEX
                or not isinstance(plen, int)
                or not 1 <= plen < verifier.HASH_HEX.get(algo, 1)):
            errors.append(f"{role} manifest has invalid hash_algo/prefix_len")
            continue
        if not isinstance(m["files"], dict):
            errors.append(f"{role} manifest 'files' must be an object")
            continue
        if _manifest_hash(m) != m["manifest_sha256"]:
            errors.append(f"{role} manifest_sha256 does not match recomputed hash")
            continue
        manifests[role] = m
    if errors:
        return errors
    base, target = manifests["base"], manifests["target"]
    if (base["hash_algo"], base["prefix_len"]) != (target["hash_algo"],
                                                   target["prefix_len"]):
        errors.append("base and target disagree on hash_algo/prefix_len")

    # the declared delta must equal the diff of the embedded manifests
    added, changed, removed = _diff_manifests(base["files"], target["files"])
    if package["added"] != added:
        errors.append("declared 'added' buckets do not match the manifest diff")
    if package["changed"] != changed:
        errors.append("declared 'changed' buckets do not match the manifest diff")
    if package["removed"] != removed:
        errors.append("declared 'removed' buckets do not match the manifest diff")

    # package self-integrity
    payload = {f: package[f] for f in
               ("format", "base", "target", "added", "changed", "removed")}
    if hashlib.sha256(_canonical(payload).encode()).hexdigest() != package["delta_sha256"]:
        errors.append("delta_sha256 does not match recomputed hash")

    # bucket files for added + changed buckets
    prefix_len = target["prefix_len"]
    bdir = os.path.join(delta_dir, "buckets")
    expect = set(added) | set(changed)
    for prefix in sorted(expect):
        if not re.fullmatch(r"[0-9A-F]{%d}" % prefix_len, prefix or ""):
            errors.append(f"bad prefix in delta: {prefix!r}")
            continue
        fpath = os.path.join(bdir, f"{prefix}.txt")
        if not os.path.isfile(fpath):
            errors.append(f"missing bucket file for prefix {prefix}")
            continue
        if _sha256_file(fpath) != target["files"][prefix]:
            errors.append(f"bucket {prefix}: sha256 mismatch with target manifest")

    # no stray files
    if os.path.isdir(bdir):
        for name in sorted(os.listdir(bdir)):
            stem = name[:-4] if name.endswith(".txt") else None
            if stem is None or stem not in expect:
                errors.append(f"unexpected file in buckets/: {name}")
    elif expect:
        errors.append("missing buckets/ directory")

    return errors


# --------------------------------------------------------------------------
# Application (atomic with respect to the mirror directory)
# --------------------------------------------------------------------------

def apply_delta(mirror_dir: str, delta_dir: str) -> dict:
    """Advance an offline mirror to the delta's target version.

    Raises DeltaError with a clear message on any failure; the mirror
    directory is then left untouched and still passes the plain export
    verifier. On success the mirror is byte-for-byte identical to a full
    export of the target version. Re-applying an already-applied delta is
    a harmless no-op.
    """
    mirror_dir = os.path.normpath(mirror_dir)
    mirror_abs = os.path.abspath(mirror_dir)
    delta_abs = os.path.abspath(delta_dir)
    if mirror_abs == delta_abs or delta_abs.startswith(mirror_abs + os.sep):
        raise DeltaError("the delta package must live outside the mirror directory")

    problems = check_delta(delta_dir)
    if problems:
        raise DeltaError(f"delta package invalid: {problems[0]}")
    package = _load_json(os.path.join(delta_dir, "delta.json"))
    base, target = package["base"], package["target"]

    if not os.path.isdir(mirror_dir):
        raise DeltaError(f"mirror directory not found: {mirror_dir}")
    mirror_manifest = _load_json(os.path.join(mirror_dir, "manifest.json"))
    if mirror_manifest is None:
        raise DeltaError(f"mirror manifest unreadable: {mirror_dir}/manifest.json")
    problems = verifier.verify_export(mirror_dir)
    if problems:
        raise DeltaError(
            f"local mirror failed verification, repair or re-export it"
            f" first: {problems[0]}")

    if mirror_manifest.get("manifest_sha256") == target["manifest_sha256"]:
        return {"status": "already-applied", "version": target["version"],
                "manifest_sha256": target["manifest_sha256"]}
    if mirror_manifest.get("manifest_sha256") != base["manifest_sha256"]:
        raise DeltaError(
            f"baseline mismatch: mirror holds version"
            f" {mirror_manifest.get('version')} (manifest"
            f" {str(mirror_manifest.get('manifest_sha256'))[:16]}...), but"
            f" this delta advances version {base['version']} (manifest"
            f" {base['manifest_sha256'][:16]}...) to version"
            f" {target['version']}")

    staging = mirror_dir + ".delta-staging"
    backup = mirror_dir + ".delta-backup"
    if os.path.exists(backup):
        raise DeltaError(
            f"a previous apply left {backup} behind; the mirror may be in"
            " an intermediate state - inspect it and remove the backup"
            " before retrying")
    shutil.rmtree(staging, ignore_errors=True)  # leftover from a crashed run

    try:
        # Stage the target tree next to the mirror; the mirror itself is
        # not modified in any way here.
        os.makedirs(os.path.join(staging, "buckets"))
        rewritten = set(package["added"]) | set(package["changed"])
        for prefix in sorted(target["files"]):
            dst = os.path.join(staging, "buckets", f"{prefix}.txt")
            if prefix in rewritten:
                src = os.path.join(delta_dir, "buckets", f"{prefix}.txt")
                shutil.copyfile(src, dst)
                with open(dst, "rb") as fh:
                    os.fsync(fh.fileno())
            else:
                _link_or_copy(os.path.join(mirror_dir, "buckets", f"{prefix}.txt"),
                              dst)
        with open(os.path.join(staging, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(target, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(os.path.join(staging, "buckets"))
        _fsync_dir(staging)
        # The staged tree must be indistinguishable from a full target
        # export before the mirror is touched.
        problems = verifier.verify_export(staging)
        if problems:
            raise DeltaError(f"staged result failed verification: {problems[0]}")
    except DeltaError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise DeltaError(
            f"interrupted while writing the staged mirror: {exc}; the"
            " original mirror is untouched") from exc

    # Commit: two renames. Until the second one the mirror path still
    # holds the complete, verifiable old tree.
    try:
        os.rename(mirror_dir, backup)
        try:
            os.rename(staging, mirror_dir)
        except BaseException:
            os.rename(backup, mirror_dir)  # roll back
            raise
    except OSError as exc:
        raise DeltaError(
            f"could not swap the staged mirror into place: {exc}") from exc
    _fsync_dir(os.path.dirname(mirror_abs) or ".")
    shutil.rmtree(backup, ignore_errors=True)
    return {"status": "applied", "from_version": base["version"],
            "to_version": target["version"],
            "manifest_sha256": target["manifest_sha256"]}
