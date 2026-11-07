# Run 419 provenance / execution receipt

- UTC execution: 2026-10-10T17:58:33Z (artifact preparation).
- Target: syscoin/PVUGC pull request 1, draft branch research/pq-wkem-validation-20260918.
- Read-first starting head: 49017d18da291d87382803384ccb0c4c753bdf29.
- Last substantive PR comment read: 6067040320, 2026-10-08.
- Exact prior blobs: Run418 67f5db445f48a35aaebb0729e4f50dc0b30cc886; Run417 368d0e86a4cbead552df856598ac05f3c309493e; CLZ c19d9d9cd515140e3ce62eac960cd548c0add622; Run259 c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2.
- Read actions: get_pr_info; fetch (issue comments last page); fetch_commit (two exact commits); fetch_file (four exact notes).
- Checker runtime: Node.js v22.16.0. Command: node research/pq-wkem/run419_compact_check.js.
- Checker result: 4,249,584 finite assertions, 292,968 unary traces, 256 bare-verdict seam fixtures; two byte-identical executions.
- Published compact note SHA-256: 35f3c8a413536ae157e4a1affcfb5e409810a062296df2258b6a7383c83dc5b1.
- Executed compact checker SHA-256: 610d34a50a5c0ec973799b3213e3ce1a48f5e83d0c11cb0a4ceb9942cfafe90a.
- Captured compact output SHA-256: 9a1bfa5532dd122a3ceb49c10f7e329a9ae38c7539f6d5e0b49c241934720830.
- Local extended proof SHA-256: 416e3ec016d1fb73d0c9e6281101195065886669be8ff893d06c553b3eb778b2.
- Local extended Python checker SHA-256: 1fa80c3e9c90e76b4f4af024df9d5b3bdc0afb73465213c233a8b627595a43ed.
- Local Python output SHA-256: d1b4fdb9ebf503ca1c978c638bbfe9ff37446670e4abba994f2ea71699598255.
- No PR diff/replay of all runs. No claims of QPT hiding, native cryptographic soundness, or completed WKEM. Production unchanged.
