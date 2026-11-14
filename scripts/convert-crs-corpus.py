#!/usr/bin/env python3
"""Convert the pinned OWASP CRS request regression tests into a decision corpus.

The upstream suite is a log-level suite: it asserts that specific rule IDs were
logged, not that the request was blocked. This converter projects each test to
the decision exposed by the WAF engines (block/allow) using the vendored PL1
rule bundle:

* ``expect_ids`` for an active PL1 rule that adds at least the critical inbound
  anomaly score (or uses a disruptive ``deny``/``drop`` action) -> ``block``.
* ``expect_ids`` for an active PL1 warning/notice rule -> ``allow`` and the
  ``detection-only`` tag, because the default anomaly threshold is not reached.
* ``no_expect_ids`` for an active PL1 rule -> ``allow``.

The converter deliberately does not invent payloads. Every request field is
copied from the upstream YAML (converted to JSON by ``yq``) and the source file
and test ID are recorded on each case.

Usage is driven by ``scripts/vendor-crs-corpus.sh``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

CATEGORY = {
    "911": "method",
    "913": "scanner",
    "920": "protocol",
    "921": "protocol-attack",
    "922": "multipart",
    "930": "lfi",
    "931": "rfi",
    "932": "rce",
    "933": "php",
    "934": "generic",
    "941": "xss",
    "942": "sqli",
    "943": "session-fixation",
    "944": "java",
    "949": "anomaly",
}

REGRESSION_TUNING_VARS = (
    "tx.arg_name_length",
    "tx.arg_length",
    "tx.max_num_args",
    "tx.total_arg_length",
    "tx.max_file_size",
    "tx.combined_file_sizes",
)

TEMPLATE_RE = re.compile(r'\{\{\s*"((?:[^"\\]|\\.)*)"\s*\|\s*repeat\s+(\d+)\s*\}\}')
TEMPLATE_LEFTOVER_RE = re.compile(r"\{\{[^}]*\|")

SMOKE_IDS = [
    "crs-911100-1",  # method, negative
    "crs-913100-1",  # scanner
    "crs-920100-1",  # protocol, negative
    "crs-920100-10",  # protocol, detection-only
    "crs-921110-1",  # protocol attack
    "crs-922100-1",  # multipart
    "crs-930100-1",  # LFI
    "crs-931100-1",  # RFI
    "crs-932120-1",  # RCE
    "crs-933100-1",  # PHP
    "crs-934100-1",  # generic
    "crs-941100-1",  # XSS
    "crs-942100-1",  # SQLi
    "crs-943100-1",  # session fixation
    "crs-944100-1",  # Java
    "crs-949110-1",  # anomaly/blocking evaluation
]


def load_rule_meta(rules_dir: Path) -> dict[int, dict]:
    meta: dict[int, dict] = {}
    for path in sorted(rules_dir.glob("REQUEST-*.conf")):
        text = path.read_text(encoding="utf-8")
        for block in re.split(r"(?m)^(?=Sec(?:Rule|Action)\b)", text):
            match = re.search(r"id:(\d+),", block)
            if not match:
                continue
            rule_id = int(match.group(1))
            severity = re.search(r"severity:'([A-Z]+)'", block)
            paranoia = re.search(r"tag:'paranoia-level/(\d+)'", block)
            meta[rule_id] = {
                "severity": severity.group(1) if severity else None,
                "paranoia": int(paranoia.group(1)) if paranoia else 0,
                "inbound_score": "inbound_anomaly_score" in block,
                "disruptive": bool(re.search(r"\b(deny|drop)\b", block)),
                "regression_tuning": any(name in block for name in REGRESSION_TUNING_VARS),
            }
    return meta


def active_pl1(rule: dict | None) -> bool:
    return rule is not None and rule["paranoia"] in (0, 1)


def expects_block(rule: dict | None) -> bool:
    if rule is None:
        return False
    if rule["disruptive"]:
        return True
    return rule["severity"] == "CRITICAL" and rule["inbound_score"]


def manifest_sha256(yaml_root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in yaml_root.glob("REQUEST-*/*.yaml")
        if path.is_file()
    )
    for path in files:
        relative = path.relative_to(yaml_root).as_posix()
        file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(f"{file_digest}  {relative}\n".encode("utf-8"))
    return digest.hexdigest()


def expand_templates(body: str) -> str | None:
    """Expand the go-ftw ``repeat`` template used by the upstream suite.

    Returns ``None`` when an unknown template remains, so the caller can skip
    the case rather than send the literal template text.
    """

    def repeat(match: re.Match) -> str:
        value = json.loads('"' + match.group(1) + '"')
        return value * int(match.group(2))

    expanded = TEMPLATE_RE.sub(repeat, body)
    if TEMPLATE_LEFTOVER_RE.search(expanded):
        return None
    return expanded


def ftw_request(input_data: dict) -> tuple[str, str, str, dict[str, str], str | None] | None:
    """Reproduce the ftw Input defaults that the upstream suite relies on."""
    method = str(input_data.get("method") or "GET")
    uri = str(input_data.get("uri") or "/")
    version = str(input_data.get("version") or "HTTP/1.1")

    headers: dict[str, str] = {}
    for name, value in (input_data.get("headers") or {}).items():
        headers[str(name)] = str(value)

    body = input_data.get("data")
    if isinstance(body, list):
        body = "\r\n".join(str(item) for item in body)
    elif body is not None and not isinstance(body, str):
        body = str(body)
    if body == "":
        body = None
    if body is not None:
        body = expand_templates(body)
        if body is None:
            return None

    if body is not None:
        content_type = next(
            (value for name, value in headers.items() if name.lower() == "content-type"),
            None,
        )
        if content_type is None:
            content_type = "application/x-www-form-urlencoded"
            headers["Content-Type"] = content_type
        if content_type == "application/x-www-form-urlencoded":
            # ftw only re-encodes when percent-decoding is a no-op and the body
            # parses as a query string.
            if urllib.parse.unquote(body) == body:
                pairs = urllib.parse.parse_qsl(body)
                if pairs:
                    body = urllib.parse.urlencode(pairs)
        if not any(name.lower() == "content-length" for name in headers):
            headers["Content-Length"] = str(len(body.encode("utf-8")))

    return method, uri, version, headers, body


def payload_size(method: str, uri: str, version: str, headers: dict[str, str], body: str | None) -> int:
    envelope = {
        "method": method,
        "uri": uri,
        "http_version": version,
        "headers": list(headers.items()),
        "body_size": len(body) if body is not None else None,
        "body_original_size": len(body) if body is not None else None,
        "body_encoding": "utf8",
        "body": body,
    }
    return len(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))


def convert(
    json_root: Path,
    yaml_root: Path,
    rules_dir: Path,
    max_payload_bytes: int,
) -> tuple[list[dict], dict[str, int], list[str]]:
    rule_meta = load_rule_meta(rules_dir)
    cases: list[dict] = []
    excluded: Counter[str] = Counter()
    warnings: list[str] = []

    for path in sorted(json_root.glob("REQUEST-*/*.yaml.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        relative = path.relative_to(json_root).as_posix()
        if relative.endswith(".json"):
            relative = relative[:-5]
        category_match = re.search(r"REQUEST-(\d{3})-", relative)
        category = CATEGORY.get(category_match.group(1), "other") if category_match else "other"

        for test in doc.get("tests") or []:
            stages = test.get("stages") or []
            if len(stages) != 1:
                excluded["multi-stage"] += 1
                continue
            stage = stages[0]
            input_data = stage.get("input") or {}
            output = stage.get("output") or {}

            if "encoded_request" in input_data or "raw_request" in input_data:
                excluded["encoded/raw request"] += 1
                continue
            if "autocomplete_headers" in input_data:
                excluded["autocomplete headers"] += 1
                continue
            if "expect_error" in output:
                excluded["expect_error"] += 1
                continue
            log = output.get("log") or {}
            if "match_regex" in log or "no_match_regex" in log:
                excluded["match_regex"] += 1
                continue

            status = output.get("status")
            expect_ids = log.get("expect_ids")
            no_expect_ids = log.get("no_expect_ids")
            if no_expect_ids is None and "no_expectids" in log:
                no_expect_ids = log.get("no_expectids")

            if not expect_ids and not no_expect_ids:
                excluded["no log expectation"] += 1
                continue
            if no_expect_ids and status is not None and status >= 400:
                # The status came from the web server, not from CRS; the test
                # cannot be projected to a CRS decision.
                excluded["negative with server-level status"] += 1
                continue

            ids = expect_ids or no_expect_ids or []
            if len(ids) != 1:
                excluded["multiple expected ids"] += 1
                continue
            rule_id = int(ids[0])
            rule = rule_meta.get(rule_id)
            if rule is None:
                excluded["unknown rule id"] += 1
                continue
            if not active_pl1(rule):
                excluded["rule above paranoia level 1"] += 1
                continue
            if rule["regression_tuning"]:
                # These rules compare against tx.* values that the upstream
                # suite sets in a test-only SecAction (id:900005). The shipped
                # bundle leaves them unset, so the rule cannot fire.
                excluded["requires upstream regression tuning"] += 1
                continue

            if expect_ids:
                expected = "block" if expects_block(rule) else "allow"
            else:
                expected = "allow"

            request = ftw_request(input_data)
            if request is None:
                excluded["unsupported template"] += 1
                continue
            method, uri, version, headers, body = request
            if payload_size(method, uri, version, headers, body) > max_payload_bytes:
                excluded["payload exceeds reactor limit"] += 1
                continue

            test_id = test.get("test_id")
            case_id = f"crs-{rule_id}-{test_id}"
            tags = ["crs", "upstream", category, "positive" if expected == "block" else "negative"]
            if expect_ids and expected == "allow":
                tags.append("detection-only")

            cases.append(
                {
                    "id": case_id,
                    "description": (
                        test.get("desc")
                        or (doc.get("meta") or {}).get("description")
                        or f"CRS rule {rule_id} test {test_id}"
                    ).strip(),
                    "request": {
                        "method": method,
                        "uri": uri,
                        "http_version": version,
                        "headers": headers,
                        "body": body,
                    },
                    "expected": expected,
                    "expected_rule_ids": [rule_id],
                    "tags": tags,
                    "source": {"file": relative, "test_id": test_id, "rule_id": rule_id},
                }
            )

    cases.sort(key=lambda case: (case["source"]["file"], str(case["source"]["test_id"])))
    seen: set[str] = set()
    for case in cases:
        if case["id"] in seen:
            warnings.append(f"duplicate id {case['id']}")
        seen.add(case["id"])
    return cases, dict(sorted(excluded.items())), warnings


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-root", required=True, type=Path)
    parser.add_argument("--yaml-root", required=True, type=Path)
    parser.add_argument("--rules-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--smoke-out", type=Path)
    parser.add_argument("--crs-version", required=True)
    parser.add_argument("--crs-commit", required=True)
    parser.add_argument("--crs-url", required=True)
    parser.add_argument("--tarball-sha256", required=True)
    parser.add_argument("--max-payload-bytes", type=int, default=60 * 1024)
    args = parser.parse_args()

    cases, exclusions, warnings = convert(
        args.json_root, args.yaml_root, args.rules_dir, args.max_payload_bytes
    )
    if not cases:
        print("error: conversion produced no cases", file=sys.stderr)
        return 1

    source = {
        "project": "OWASP Core Rule Set",
        "version": args.crs_version,
        "commit": args.crs_commit,
        "url": args.crs_url,
        "sha256": args.tarball_sha256,
        "license": "Apache-2.0",
        "upstream_path": "tests/regression/tests/REQUEST-*",
        "exclusions": exclusions,
        "source_manifest_sha256": manifest_sha256(args.yaml_root),
        "converter": "scripts/convert-crs-corpus.py",
        "generated_from": (
            "request-phase regression YAML at the pinned CRS commit, projected to "
            "the default PL1 block/allow decision"
        ),
    }
    corpus = {"format_version": 1, "source": source, "cases": cases}
    write_json(args.out, corpus)

    if args.smoke_out:
        by_id = {case["id"]: case for case in cases}
        smoke_cases = [by_id[case_id] for case_id in SMOKE_IDS if case_id in by_id]
        missing = [case_id for case_id in SMOKE_IDS if case_id not in by_id]
        if missing:
            print(f"warning: smoke cases missing: {missing}", file=sys.stderr)
        write_json(
            args.smoke_out,
            {"format_version": 1, "source": source, "cases": smoke_cases},
        )

    print(f"cases={len(cases)}")
    print(f"expected={dict(Counter(case['expected'] for case in cases))}")
    print(f"tags={dict(Counter(tag for case in cases for tag in case['tags']))}")
    print(f"exclusions={exclusions}")
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
