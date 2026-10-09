# Archival restoration: Runs 391, 392, 395, 396 and 397

This is a user-requested restoration of historical research, not a new research run, a breakthrough, a general local-mixing impossibility theorem, or a complete witness-KEM.

Starting branch: `research/pq-wkem-validation-20260918`, commit `3e2628f58190d29a1d43fe692ae6597a74a6b2ba` (Run 400). The restoration preserves that history without force, production changes, reviews or merging.

## Restored records

- [Run 391](SHALLOW_MIXER_DERIVATIVE_BARRIER_RUN391.md): shallow exposed forward-mixer algebraic-degree limitation. The exact four compact Git blobs come from previously unreferenced commit `539089b2deeb047d7090f0314b37edfc927a86a8`.
- [Run 392](LIGHTCONE_TWOQUERY_BRIEF_RUN392.md): two-query causal-cone limitation, under its specified locality, depth and public-oracle interface. The exact four compact Git blobs come from `bc532878491a2595007a7f3494c56d523f30b9df`.
- [Run 395](WITNESSED_ZERO_WORLD_SEPARATION_RUN395.md): known-witness real/zero-program indistinguishability restriction. The exact four compact Git blobs come from `a01972eb6ec122a1644e49539e42f054de592762`.
- [Run 396](FRONTIER_STATE_SIMULATION_BARRIER_RUN396.md): historical complete-input simulation lemma. Its note, both checkers, both captured outputs and original provenance are copied from the preserved local archive.
- [Run 397](UNARY_ORBIT_LATE_ADMISSION_RUN397.md): fixed-unary, polynomially enumerable interface limitation. Its note, both checkers, both captured outputs and original provenance are copied from the preserved local archive.

Runs 391, 392 and 395 were attached in restoration commit `5c78f7951d5b9b8c6b847de2b47676cf5240c0b5` (12 additions). The next restoration commit adds Runs 396 and 397 and this index. The historical provenance files intentionally retain the outcomes and timestamps of their original executions; their former publication-failure fields do not describe this restoration. Run 396's historical note says its Python checker was local-only; that checker is included here as well.

## Important scope correction

Run 396 assumes an independently callable release boundary and an efficiently reproducible COMPLETE JOINT input distribution. It does not prove those premises for a source-bound local mixer. Its direct conclusion is an authorization-probability bound. Not being supplied an ORIGINAL witness does not by itself exclude finding one or extracting one from the sampled state; a full attack on the intended extraction game must address that distinction.

[Run 400](PROJECTION_CAUSAL_VIEW_RUN400.md) is the later projected-causal-view formulation. Neither result establishes that local mixing or the intended witness-dependent-state architecture is impossible. Run 397 likewise does not refute the full CLZ system or additional input-sensitive operations. These records should prevent repetition of rejected restricted interfaces, not displace constructive source-bound release work.

## Restoration checks

The original archive Python checkers for Runs 391, 392, 395, 396 and 397 were rerun in this restoration. They returned respectively 283573, 213188, 17321120, 242082 and 44072 checks, reproducing their original captured stdout byte-for-byte. The original Run 396 and 397 JavaScript checkers were also rerun: 242074 and 16764 checks, with byte-identical captured output.

The local extended Python variants for 391, 392 and 395 are distinct from their compact GitHub JavaScript variants; the Python counts above are not attributed to the JavaScript files. The JavaScript files and original validations for those three runs are preserved unchanged.

## Reproduction entry points

Run 391's historical JavaScript file defines `main` without invoking it; Run 392 evaluates to a JSON string without printing it. Use these explicit wrappers rather than interpreting empty stdout as successful validation:

```sh
node -e 'const fs=require("fs"),vm=require("vm");vm.runInThisContext(fs.readFileSync(process.argv[1],"utf8"));console.log(JSON.stringify(main(),null,2));' research/pq-wkem/shallow_local_derivative_run391_check.js
node -e 'const fs=require("fs"),vm=require("vm");process.stdout.write(vm.runInThisContext(fs.readFileSync(process.argv[1],"utf8")));' research/pq-wkem/lightcone_twoquery_run392_check.js
node research/pq-wkem/witnessed_zero_world_run395_check.js
python3 research/pq-wkem/frontier_state_simulation_run396_check.py
node research/pq-wkem/frontier_state_simulation_run396_check.js
python3 research/pq-wkem/unary_orbit_admission_run397_check.py
node research/pq-wkem/unary_orbit_run397_compact_check.js
```

Finite tests do not prove concrete QPT security. This restoration does not claim to fix every older publication gap, repair the separate Run 398 checker, prove a practical WKEM, or establish scheduled-execution restoration. The PR remains draft and unmerged.
