# R170 reproducibility and exact scope

Local run: two byte-identical invocations of checker.py, and two byte-identical invocations of distribution_equivalence.py, using Python 3 standard library only. Only finite mathematical / simulation checks; not a quantum attack executed on real SHA, a secure witness KEM, or actual BTC/SYS consensus.

The actual executed main Python source SHA256 is 40fed021f44b5c53114fca1e3348bb006c590460d58722c1dfbd875f414d2aea (Git blob 64ab7339f0233b2b2d43562faaa77383051e6b3e). The actual captured stdout SHA256 is 46fb0d075cb8e6028814c8a896ad4054e1436e9c8f3fa9c0e1f2e4776635b872. Exact finite distribution source SHA256 is dcd5f27db6918a84e732dad711d472c2f460d9b5c55f1934df762ec3c15c5d2b; its captured stdout SHA256 dca6c990d286b007b10be375a3b04a72ba64d8c5a40ec70dbe8978dd12a285a1.

GitHub start: 3ed1a91f857a6a277ad6240c9aa810127ef4becb. Interim note/first math commit: 7769d5eb13afaa199658c990ab35561f59b9015a. No ordinary top-level PR comment, because this does not solve the ORIGINAL source compiler. No external web or independent agent was used.

Run locally from repo root:
python research/pq-wkem/r170_oracle_transplant_20261109/checker.py
python research/pq-wkem/r170_oracle_transplant_20261109/distribution_equivalence.py

Next foundational task: non-black-box fixed-SHA/AuxPoW computation-trace binding with hidden SAME capability across all ORIGINAL witnesses and a full-public QPT reduction. No size optimization or lattice fallback.
