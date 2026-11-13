# MINK-LWE-PRG-20261102-T20 provenance

Research-only continuation of syscoin/PVUGC draft PR #1 on research/pq-wkem-validation-20260918. Verified starting head 557e9cdbaf29243a3adb40f50c86446344caa507 (open, draft, unmerged). The actual current PR metadata and last five substantive ordinary comments were read, newest comment 6569361522. Exact predecessor research file read at that head: research/pq-wkem/mink_seeded_lamport_20261102/RESEARCH.md, Git blob 251d6b579eddf3619e3e6102e07b88468f90bc15. No entire-PR diff, archive sweep, web search or fetched external literature.

Novel candidate step: construct the deterministic length-expanding LWE generator from a uniform encoded (s,e) seed, then prove its 15-stage same-public-A hybrid against precisely stated decisional QPT LWE. Plug this into the **restricted** previous SOURCE/seeded-Lamport release, eliminating its standalone SHAKE256-PRG assumption at higher SOURCE and CRS cost. The full general NP SOURCE and hard-TRUE ORIGINAL extraction are NOT solved.

Actually executed:
- Published exact checker.js via Node twice, byte-identical outputs, 7,354 assertions per process; output in VALIDATION.json. Expected Git blob hash of that exact JS file: 7fa067a66d8b031ddec7ab901d11ff51fb2d67dd.
- Separately ran full-size Python-standard-library checker.py twice, with 1,216,696 assertion events per process and byte-identical output. It exercises complete n=256,m=4096,q=65536,a=10, 15-step PRG, real SHA384 Lamport sign/verify, two distinct witnesses, FALSE-source distribution, allowed openings and bound manifest. Its SHA256 source hash: 3568cb188754b96cb1bc350beb1e2dbc658a60bc64e758aa686d45ebf953b610.
- Full-size Python source and paired results are local-only in a separate archive; no GitHub publication of those Python bytes is claimed. Exact local offline tar archive SHA256: 6a882bec49e0b08bdca34d59f43f67639748f09c93f5820b8f1d2c9dbfa761ae.
- A preliminary Python syntax error and undersized fixture-bitstream allocation were repaired before final passing executions. A subsequent change added PRG A/capsule digests to the typed challenge manifest, then both final checks reran. Preliminary failures were not counted as passes.

No independent agent, quantum hardness assessment, Bitcoin deployment or production edit. Fixture randomness is deterministic SHAKE256 *for reproducibility*, not a real setup entropy proof.

Any GitHub commit and ordinary comment are separately verified actions; creating these Git blobs alone is not evidence of branch publication.