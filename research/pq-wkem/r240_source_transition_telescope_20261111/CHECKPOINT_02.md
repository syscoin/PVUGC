# R240 checkpoint 2 — after first checker and before fingerprint repair

The first local checker executed twice with identical output: research.py SHA256 937ddc17f5a8c7a091715a4fd290bc983cecf505db14f53bad1dc05ac75a0e4e; first.json SHA256 c947a9645a22d6400eb65dc70e85df8f41979a9c06ee4249c03c1bb36326dd83.

XOR masks released sigma in a graph with NO directed accepting source path (S->Q<-A) through a reversible undirected walk. Directional hash-locked edges prevented that one backward traversal in the fixture, but a locally relaxed false relation [x=0 AND x=1] still opened. Explicit graph BFS obtains any reachable accepting key. Exact layered path-graph consistency for EQ_n needs at least 2^n distinct midpoint states; a formal fooling-set proof is in RESEARCH.md, not an arbitrary NP/WE impossibility theorem.

Next attempt: bind every source bit occurrence to one global Merkle fingerprint, then test whether a fixed preauthorization edge mask can accept two distinct future authenticated source roots without revealing the secret to unauthenticated source choices. Do not report completion.
