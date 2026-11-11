# R225 checkpoint — native cancellation portability across alternate SegWit activations

Run target: the R191/R216 fixed-txid preauthorization with later one-notary witness activation. Research-only; not a hash-based witness encryption or BTC/SYS test.

Hypothesis recorded before executing the local checker: if the nonwitness serialization B of an activation is fixed, distinct witness assertions W0 and W1 produce the SAME txid and UTXO but different wtxids. A frozen native cancellation signature spending that UTXO cannot distinguish the creator's witness because Bitcoin does not automatically introspect it.

A source-admissible absent-burn fault in one Bitcoin history might unlock the cancellation signature for a different history whose activation is legitimate, despite each branch having independently committed to its correct wtxid. This is conditional on BOTH source histories being admitted by the ORIGINAL relation. If the policy defines any admitted fault as a slot-global veto, the transfer is intended behavior; otherwise it is a source/endpoint scope defect.

Proposed repairs to test: explicit slot-global veto with carefully bounded source admission; native activation-specific outpoint or enforceable commitment; freeze claim-specific txid before N-of-N ceremony. Merely authenticating wtxid off-chain does not constrain a previously signed native cancellation message.

This checkpoint is a hypothesis and test plan, not proof of cryptographic release, quantum security, or a deployed vulnerability.
