# HPW — Checkpoint 2: test source-qualified PoW as a hash-release carrier

Status: experiment started, no security or source-binding success claimed.

Continuity: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, observed start HEAD 45a465dadd9c0271c8036b62cca9c69f61668ca9 (open/draft/unmerged). Preceding checkpoint: hpw_20261108/CHECKPOINT_01.md blob 010b3bea5755b780e05e91860c1818bb2560ace7. Last substantive ordinary PR comment R153 6718361572. Offline except authorized project connector. Research-only directory.

## Candidate: source-qualified prefix-reveal work, not a replacement for actual source validity

Setup: sample uniform K in {0,1}^d, freeze native signature sigma of bound challenge message M, publish CK=H_check(context,K) and D=sigma XOR H_mask(context,K). Here H_check, H_mask, H_pow use independent domain separation.

Proposed public evidence path: given original source certificate w for R_ORIGINAL(x,w)=1, search nonce nu for prefix_d(H_pow(context, Enc(w), nu))=K. The nonce can be included in an AuxPoW-like additional work certificate; the *original* certificate should bind actual Syscoin child header, BTC parent linkage, coinbase tag, ancestor/slot, interval and claim context. Public Open decodes K from the work digest, checks CK, and unseals sigma.

This is a deliberately concrete attempted way for **future** source work to release a key chosen by setup. It does not assume miners know K: they can test CK on each digest prefix. A miner finding any digest with matching commitment learns K.

## Required adversarial test

1. Can a fabricated, source-invalid w_fake be hashed and mined until the same CK matches, even if honest Open checks R_ORIGINAL(x,w_fake) and refuses it? If so, a raw attacker can unmask D and ignore Open. No ORIGINAL witness has been extracted.
2. Does committing the capsule root inside a synthetic parent coinbase fix the problem, or does it only make even the **invalid** work string self-consistent?
3. For ideal d-bit digest prefixes, is P(hit after N independent queries)=1-(1-2^-d)^N for valid and invalid source strings alike, with expected cost 2^d? If true, hiding 256 bits for ~128-bit generic quantum preimage resistance requires expected 2^256 honest tries, not practical; reducing d does not repair source soundness.
4. Can a multi-source/hash-sharing variant change the proof that invalid bytes can access H_pow, without an online secret releaser, a hidden trapdoor already knowing w, or an unimplemented input-validity-gated oracle?

This checkpoint records an explicit repair attempt to the missing Build/PublicDerive interface, not a theorem or completed experiment. No lattice, public group, compression or standalone size optimization.
