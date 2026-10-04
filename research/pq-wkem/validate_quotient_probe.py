#!/usr/bin/env python3
"""Reproduce the captured algebra checks without overwriting their evidence."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import unittest


def main() -> int:
    root = Path(__file__).resolve().parent
    started = datetime.now(timezone.utc).isoformat()
    log = io.StringIO()
    suite = unittest.TestLoader().discover(str(root / 'tests'))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    files = ['moment_compiler.py', 'constraint_quotient.py', 'linear_probe.py',
             'tests/test_moment_compiler.py', 'tests/test_constraint_quotient.py',
             'tests/test_linear_probe.py', 'QUOTIENT_AND_PROBE.md',
             'validate_quotient_probe.py']
    hashes = {}
    for name in files:
        data = (root / name).read_bytes()
        hashes[name] = {
            'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode()
                                        + b'\0' + data).hexdigest(),
            'bytes': len(data)}
    report = {
        'status': 'algebraic validation only; not a completed or secure WKEM',
        'started_utc': started,
        'finished_utc': datetime.now(timezone.utc).isoformat(),
        'python': platform.python_version(),
        'base_commit': '9489a2a246018ae673a148c18a302fcf235dfceb',
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped),
        'success': result.wasSuccessful(),
        'source_hashes': hashes,
        'test_output': log.getvalue(),
        'scope': {
            'external_research': 'none; requested GitHub reads/writes only',
            'prime_fields_only': True,
            'full_security_reduction': False,
            'general_key_recovery_extractor': False,
            'historical_checkpoint8_counts': 'independently reconstructed, not additive coverage',
            'randomness': 'fixed-seed public algebra fixtures, not cryptographic sampling',
        },
    }
    target = root / 'quotient-probe-validation-latest.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(log.getvalue(), end='')
    print('Saved', target)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
