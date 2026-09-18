"""Rerun public semantic tests and emit a reproducible evidence report.

No cryptographic security estimate is computed. No network calls occur.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import itertools
import json
import platform
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from moment_compiler import extract_moments, flatten, monomials, rank


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).with_name("validation-latest.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    start = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(root / "tests"))
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    census = []
    for n, degree, p in ((3, 3, 2), (3, 3, 3), (2, 3, 5), (3, 4, 2), (3, 5, 3)):
        tested = applicable = max_atoms = 0
        for mu in itertools.product(range(p), repeat=len(monomials(n, degree))):
            tested += 1
            d = rank(flatten(mu, n, degree, p), n + 1, p)
            if 0 < d < degree:
                atoms = extract_moments(mu, n, degree, p)
                applicable += 1
                max_atoms = max(max_atoms, len(atoms))
        census.append(dict(n=n, degree=degree, field_prime=p, moments_tested=tested,
                           applicable_extractions=applicable, max_atoms=max_atoms))
    source_hashes = {path.relative_to(root).as_posix():
                     hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in (root / "moment_compiler.py", root / "validate.py",
                                  root / "tests" / "test_moment_compiler.py")}
    report = dict(
        status="semantic-tests-only; not a WKEM or PQ security proof",
        start_utc=start, end_utc=datetime.now(timezone.utc).isoformat(),
        wall_seconds=time.perf_counter() - clock, python=platform.python_version(),
        test_groups=result.testsRun, failures=len(result.failures),
        errors=len(result.errors), skipped=len(result.skipped),
        passed=result.wasSuccessful(), source_sha256=source_hashes,
        census=census, census_total=sum(row["moments_tested"] for row in census),
        census_note="The census intentionally repeats unit-test fixtures; do not add them as distinct coverage.",
        test_log=stream.getvalue())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(stream.getvalue(), end="")
    print(json.dumps({"passed": report["passed"], "census": census,
                      "output": str(args.output)}, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
