"""Command-line interface for shimforge."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger("shimforge")


def _load(mod: str):
    try:
        return __import__(f"shimforge.{mod}", fromlist=["*"])
    except ImportError as exc:
        raise SystemExit(f"shimforge.{mod} is not available: {exc}")


def cmd_oracle(args: argparse.Namespace) -> int:
    oracle_check = _load("oracle_check")
    cfg = oracle_check.OracleConfig.load(args.config)
    report = oracle_check.check_oracle(cfg, write_policy=args.write_policy)
    payload = json.dumps(report.to_json(), indent=2, ensure_ascii=False)
    if args.report_out:
        report_path = Path(args.report_out)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(payload + "\n", encoding="utf-8", newline="\n")
    if args.json:
        print(payload)
    else:
        print(report.render())
    return 0 if report.ok else 1


def cmd_diff(args: argparse.Namespace) -> int:
    model = _load("model")
    trace = _load("trace")
    policy_mod = _load("policy")
    normalize = _load("normalize")
    tracediff = _load("tracediff")
    oracle_check = _load("oracle_check")

    contract = model.Contract.load(args.contract)
    policy = (policy_mod.Policy.load(args.policy) if args.policy
              else policy_mod.Policy.derive(contract))
    # A broad mask, ignored symbol, non-zero epsilon, or bounded callback walk
    # can manufacture a clean result.  Refuse such a policy before touching
    # the evidence; core tracediff repeats this gate for non-CLI callers.
    try:
        assert_safe = getattr(policy, "assert_safe", None)
        if callable(assert_safe):
            assert_safe(strict=True, contract=contract)
    except (TypeError, ValueError) as exc:
        if args.json:
            print(json.dumps({"ok": False, "conclusive": False,
                              "error": str(exc)}, indent=2,
                             ensure_ascii=False))
        else:
            print(f"tracediff refused unsafe policy: {exc}", file=sys.stderr)
        return 2
    try:
        l0_report = _load_l0_report(args.l0_report)
        l0_problems = _l0_binding_problems(args, l0_report, oracle_check)
    except (OSError, ValueError, TypeError) as exc:
        l0_problems = [f"L0 report cannot be validated: "
                       f"{type(exc).__name__}: {exc}"]
    if l0_problems:
        if args.json:
            print(json.dumps({
                "ok": False, "conclusive": False,
                "error": "L2 is not bound to an admissible L0 PASS",
                "problems": l0_problems,
            }, indent=2, ensure_ascii=False))
        else:
            print("tracediff refused unbound L0 evidence:", file=sys.stderr)
            for problem in l0_problems:
                print(f"  - {problem}", file=sys.stderr)
        return 2
    raw_a = trace.read_trace(args.a)
    raw_b = trace.read_trace(args.b)
    subject_a = _sha256_file(args.a_binary)
    subject_b = _sha256_file(args.b_binary)
    for side, raw, binary, actual in (
            ("A", raw_a, args.a_binary, subject_a),
            ("B", raw_b, args.b_binary, subject_b)):
        recorded = raw.header.get("subject")
        if recorded != actual:
            raw.validation_errors.append(
                f"{side} trace subject {recorded!r} does not match SHA-256 "
                f"{actual} of {binary}")
    # Contract conformance is independent of A/B equality.  Attach every raw
    # defect before normalization so symmetric omissions cannot disappear into
    # a clean differential.
    for raw in (raw_a, raw_b):
        raw.validation_errors = list(dict.fromkeys(
            list(raw.validation_errors)
            + trace.validate_trace_contract(raw, contract)
            + oracle_check.trace_approval_coverage_problems(raw, contract)))
    a = normalize.normalize(raw_a, contract, policy)
    b = normalize.normalize(raw_b, contract, policy)
    result = tracediff.diff(
        a, b, policy, stop_after=args.stop_after,
        require_distinct_subjects=True)

    if args.json:
        print(json.dumps(result.to_json(), indent=2, ensure_ascii=False))
    else:
        print(result.render(verbose=args.verbose))
    return 0 if result.ok else 1


def cmd_surface(args: argparse.Namespace) -> int:
    pe_surface = _load("pe_surface")
    surface = pe_surface.read_exports(args.dll)
    print(f"module : {surface.module}  ({surface.arch})")
    print(f"exports: {len(surface.exports)}")
    if args.consumers:
        names, ords = pe_surface.required_surface(
            args.consumers, Path(args.dll).name)
        print(f"required by consumers: {len(names)} by name, "
              f"{len(ords)} by ordinal")
        for n in sorted(names):
            mark = "" if n in surface.exports else "   <-- NOT EXPORTED"
            print(f"  {n}{mark}")
        for o in sorted(ords):
            e = surface.by_ordinal.get(o)
            print(f"  #{o} {'-> ' + (e.name or '(noname)') if e else '<-- NOT EXPORTED'}")
    return 0


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def _reject_json_constant(token: str) -> object:
    raise ValueError(f"non-finite JSON number {token!r} is forbidden")


def _load_l0_report(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8-sig") as stream:
        value = json.load(
            stream, object_pairs_hook=_json_no_duplicates,
            parse_constant=_reject_json_constant)
    if type(value) is not dict:
        raise ValueError("L0 report must be a JSON object")
    return value


def _l0_binding_problems(args: argparse.Namespace, report: dict,
                         oracle_check: object) -> list[str]:
    """Bind L2 to the exact immutable L0 PASS and its reference trace."""
    problems: list[str] = []
    expected_schema = getattr(
        oracle_check, "ORACLE_REPORT_SCHEMA", "shimforge-oracle/2")
    if report.get("schema") != expected_schema:
        problems.append(
            f"L0 report schema must be {expected_schema!r}, got "
            f"{report.get('schema')!r}")
    if report.get("ok") is not True:
        problems.append("L0 report is not an exact PASS")
    outcomes = report.get("outcomes")
    expected = tuple(getattr(oracle_check, "CHECK_ORDER", ()))
    by_name: dict[str, dict] = {}
    if type(outcomes) is not list:
        problems.append("L0 outcomes must be an array")
        outcomes = []
    for item in outcomes:
        if type(item) is not dict or type(item.get("name")) is not str:
            problems.append("L0 outcome entry is malformed")
            continue
        name = item["name"]
        if name in by_name:
            problems.append(f"duplicate L0 outcome {name!r}")
        by_name[name] = item
    if set(by_name) != set(expected):
        problems.append("L0 report must contain exactly these gates: "
                        + ", ".join(expected))
    for name in expected:
        item = by_name.get(name, {})
        if item.get("ok") is not True or item.get("skipped") is not False:
            problems.append(f"L0 gate {name!r} is not an unskipped PASS")
        if type(item.get("data")) is not dict:
            problems.append(f"L0 gate {name!r} has malformed evidence data")

    evidence = report.get("evidence")
    if type(evidence) is not dict:
        return problems + ["L0 evidence must be an object"]
    if evidence.get("verified_unchanged_after_run") is not True:
        problems.append("L0 artifacts were not verified unchanged after run")
    stored_manifest = evidence.get("manifest_sha256")
    manifest_body = {
        key: value for key, value in evidence.items()
        if key not in {"manifest_sha256", "verified_unchanged_after_run"}}
    try:
        encoded = json.dumps(
            manifest_body, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")
        actual_manifest = hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError) as exc:
        problems.append(f"L0 manifest is not canonical JSON: {exc}")
        actual_manifest = ""
    if (type(stored_manifest) is not str
            or stored_manifest != actual_manifest):
        problems.append("L0 manifest SHA-256 is invalid")

    artifacts = evidence.get("artifacts")
    by_role: dict[str, dict] = {}
    if type(artifacts) is not list:
        problems.append("L0 artifacts must be an array")
        artifacts = []
    hasher = getattr(oracle_check, "_sha256_artifact", None)
    if not callable(hasher):
        problems.append("artifact re-hash implementation is unavailable")
    for item in artifacts:
        if type(item) is not dict:
            problems.append("L0 artifact entry is malformed")
            continue
        role, artifact_path = item.get("role"), item.get("path")
        kind, digest = item.get("kind"), item.get("sha256")
        if (type(role) is not str or type(artifact_path) is not str
                or kind not in {"file", "directory"}
                or type(digest) is not str):
            problems.append("L0 artifact fields are malformed")
            continue
        if role in by_role:
            problems.append(f"duplicate L0 artifact role {role!r}")
        by_role[role] = item
        if callable(hasher):
            try:
                current_kind, current_digest = hasher(Path(artifact_path))
            except Exception as exc:
                problems.append(
                    f"L0 artifact {role!r} cannot be re-hashed: "
                    f"{type(exc).__name__}: {exc}")
            else:
                if (current_kind, current_digest) != (kind, digest):
                    problems.append(f"L0 artifact {role!r} changed after PASS")

    expected_hashes = {
        "contract": _sha256_file(args.contract),
        "original_dll": _sha256_file(args.a_binary),
        "tap_dll": _sha256_file(args.tap_binary),
    }
    for role, digest in expected_hashes.items():
        item = by_role.get(role)
        if item is None:
            problems.append(f"L0 report has no {role!r} artifact")
        elif item.get("kind") != "file" or item.get("sha256") != digest:
            problems.append(
                f"L0 {role!r} artifact is not the file supplied to L2")
    required_verifier_roles = {
        f"verifier:{name}" for name in (
            "oracle_check.py", "runner.py", "model.py", "trace.py",
            "normalize.py", "tracediff.py", "policy.py", "pe_surface.py")}
    missing_verifier = sorted(required_verifier_roles - set(by_role))
    if missing_verifier:
        problems.append("L0 report does not bind the complete verifier: "
                        + ", ".join(missing_verifier))

    reference_digest = _sha256_file(args.a)
    coverage_data = by_name.get("coverage", {}).get("data")
    coverage_digest = (coverage_data.get("trace_sha256")
                       if type(coverage_data) is dict else None)
    if coverage_digest != reference_digest:
        problems.append(
            "L2 A trace is not the exact coverage trace approved by L0")
    determinism_data = by_name.get("determinism", {}).get("data")
    determinism_digests = (determinism_data.get("trace_sha256")
                           if type(determinism_data) is dict else None)
    if (type(determinism_digests) is not list
            or reference_digest not in determinism_digests):
        problems.append(
            "L2 A trace is not one of the exact L0 determinism traces")
    return list(dict.fromkeys(problems))


def cmd_gentap(args: argparse.Namespace) -> int:
    model = _load("model")
    gen_tap = _load("gen_tap")
    pe_surface = _load("pe_surface")
    contract = model.Contract.load(args.contract)
    original_surface = pe_surface.read_exports(args.original_dll)
    out = gen_tap.generate_tap(
        contract, args.out, real_module=args.real_module,
        surface=original_surface)
    for k, v in out.items():
        print(f"{k}: {v}")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    model = _load("model")
    policy_mod = _load("policy")
    contract = model.Contract.load(args.contract)
    policy = policy_mod.Policy.derive(contract)
    policy.save(args.out)
    auto = sum(1 for m in policy.masks if getattr(m, "auto", False))
    print(f"wrote {args.out}: {len(policy.masks)} mask rules ({auto} auto-derived)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="shimforge",
                                description="DLL shim verification toolkit")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("oracle", help="L0 oracle self-verification")
    o.add_argument("--config", required=True)
    o.add_argument("--write-policy", action="store_true",
                   help=("legacy compatibility flag; strict verification "
                         "rejects auto-suggested masks"))
    o.add_argument("--json", action="store_true")
    o.add_argument("--report-out",
                   help="write the full JSON evidence report for a later "
                        "L2 --l0-report binding")
    o.set_defaults(fn=cmd_oracle)

    d = sub.add_parser("diff", help="L2 trace differential")
    d.add_argument("--a", required=True, help="reference trace (old DLL)")
    d.add_argument("--b", required=True, help="candidate trace (shim)")
    d.add_argument("--a-binary", required=True,
                   help="original DLL whose SHA-256 must bind trace A")
    d.add_argument("--b-binary", required=True,
                   help="candidate DLL whose SHA-256 must bind trace B")
    d.add_argument("--tap-binary", required=True,
                   help="exact tap DLL SHA-256-bound by the L0 PASS report")
    d.add_argument("--l0-report", required=True,
                   help="successful Oracle --json report whose coverage "
                        "trace must be exactly trace A")
    d.add_argument("--contract", required=True)
    d.add_argument("--policy")
    d.add_argument("--stop-after", type=int, default=1,
                   help="0 = report every divergence")
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=cmd_diff)

    s = sub.add_parser("surface", help="inspect PE export/import surface")
    s.add_argument("--dll", required=True)
    s.add_argument("--consumers", nargs="*", default=[])
    s.set_defaults(fn=cmd_surface)

    g = sub.add_parser("gentap", help="generate tap proxy sources")
    g.add_argument("--contract", required=True)
    g.add_argument("--original-dll", required=True,
                   help="original DLL whose complete export surface must "
                        "exactly match the contract")
    g.add_argument("--out", required=True)
    g.add_argument("--real-module")
    g.set_defaults(fn=cmd_gentap)

    pol = sub.add_parser("policy", help="derive a normalization policy")
    pol.add_argument("--contract", required=True)
    pol.add_argument("--out", required=True)
    pol.set_defaults(fn=cmd_policy)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
