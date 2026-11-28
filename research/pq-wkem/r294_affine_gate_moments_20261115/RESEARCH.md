# R294 — local tuple-mask affine hull and degree hierarchy (NONQUALIFYING)

## Continuity
Continuing R293 at blob f09417e1a31cfdd05f67af7731ad4450ff409e35. Starting syscoin/PVUGC PR #1 head d5a3529d469c4319341fb2b8b1c5c0b1c847c794, open/draft on research/pq-wkem-validation-20260918; latest substantive ordinary comment R225 #6796383617. This is an offline algebraic construction-and-repair test, **not** an ORIGINAL source-release result, deployment recommendation, Core test, or QPT security experiment. No web/external literature. Activated Core #609 modern chain ID, exact tags, context and parent-certificate provenance remain unchanged as source requirements, not implemented here.

## Generalized public Build/Open candidate

With n shared Boolean variables, m publicly enumerated local accepted-tuple sets S_i subset {0,1}^n, and frozen 256-bit K, let M_d(a)=(prod_(j in t) a_j)_(|t|<=d) be the degree-d squarefree GF(2) moment vector including constant 1. Build samples independent uniform factor shares k_i subject to XOR_i k_i=K. For each nonconstant t, choose independent uniform r_(i,t) subject to XOR_i r_(i,t)=0. Publish for every allowed a in S_i:

    T_(i,a) = k_i XOR XOR_(1<=|t|<=d) ((prod_(j in t) a_j) r_(i,t)).

For any common satisfying assignment a, Open XORs T_(i,a) over all factors and returns **the same K**. No after-the-fact SourceCheck protects recovered K.

**Exact symbolic-span characterization:** Let Hull_d(S_i) be the set of XORs of an odd number of degree-d moment vectors from permitted tuples. K lies in the public symbolic linear span of all token expressions **iff** intersection_i Hull_d(S_i) is nonempty. Proof: to obtain K every factor must contribute an odd number of its tokens (factor shares), and every nonconstant mask basis coefficient must be equal across factors (zero-XOR masks); these conditions precisely encode a common moment vector including constant coordinate 1. A common vector need not equal M_d(w) for an ACTUAL witness. GF(2) elimination supplies public coefficients: source-free extraction does not rely on volunteered adversary state. If the span excludes K, independent-uniform-pad setup gives complete-public perfect FALSE hiding for this restricted algebraic model, including arbitrary QPT postprocessing of its sampled classical transcript, but not malicious-setup/auxiliary-data composition.

## Reproducible complete-public FALSE extraction

Take n=2 and four clauses S_q={0,1}^2 excluding each q in turn. All four cannot hold. At d=1, choose common target M_1(00). For the clause excluding 00, publicly combine tokens for 01,10,11: M_1(01) XOR M_1(10) XOR M_1(11)=M_1(00). For each other clause select its 00 token. XORing all six *published token bytes* gives K despite FALSE. No private builder key is used by attacker.

More generally choose n bits and 2^n all-forbidden clauses. For d<n, XOR_(a in {0,1}^n) M_d(a)=0, since every degree-j monomial has 2^(n-j) occurrences, even for j<n. Thus each excluded M_d(q) equals the XOR of the other 2^n-1 allowed moment vectors. At d=n, the full squarefree-monomial evaluation matrix is invertible and the excluded row is not in the span. This **restricted** false relation needs degree n (2^n monomial positions); it is not a lower bound for arbitrary SHA-WE.

## Limited constructive SHA gate repair

For actual SHA Boolean bit functions Ch and Maj, and full-adder logic, the graph equations are quadratic over GF(2):

    v_Ch + z + xy + xz = 0
    v_Maj + xy + xz + yz = 0
    s + x + y + c = 0
    carry_out + xy + xc + yc = 0.

Degree-two local moments exclude every invalid truth tuple from the affine span of the valid gate tuples. At degree one, all 8 wrong Ch rows and all 8 wrong Maj rows are spanned; for the full adder 8/24 wrong rows remain spanned, with 16 rejected by linear sum parity. This is a genuine **single-gate** algebraic repair, but neither a global SHA circuit proof nor a source-conditioned secret release. In particular, factor-token combinations can still produce FALSE recovery without one consistent global assignment, as the all-forbidden n=3,4 systems show.

## Executed checker and limitations

Python3 stdlib script constructed actual 256-bit public token words, performed GF(2) elimination, recovered K on false n=2/3/4 systems for all d<n and failed public row recovery at d=n. Tested full Ch/Maj/full-adder truth-table spans. 269 assertions per successful run, two final runs byte-identical. SHA256 used **only** to deterministically generate synthetic masks, not as proof of PQ security.

Local-only complete derivation, checker, outputs and provenance archive: R294_affine_gate_moments_20261115.tar.gz SHA256 7eb8428b27d8060f515d8de30610b846f8947159ff4c45cd99371bc5ca4d6e17. checker.py SHA256 9e81ba44d81cd6d7e85f4fd92f368ac52a4447c3959858656cd007e01a08675f. run1.json and run2.json each SHA256 9b3a6aeaac39785f556d841b648b9d5d31835fd29aad3bd488b2713f3bcc6608. An early local assertion assuming no affine full-adder violations was corrected; those failed runs are not counted.

## Exact remaining challenge

Build_inc(x_W,sigma_cancel) and public Open_inc(C,w) must return the **same frozen native-safe cancellation** on EVERY qualified ORIGINAL evidence of higher-work BTC history, particular burn defect, or qualified Syscoin inconsistency/tag fault; unauthenticated or irrelevant evidence must not release anything. Need a **polynomial-size cryptographically enforced global-integrality/source-authentication mechanism** so recovery from complete public state (including auxiliary, correlated sibling capsules, malicious setup and native VK/message) implies an ACTUAL qualifying original certificate or independent hash/native break against arbitrary QPT adversaries. Local degree-two SHA gates are insufficient; full-order moments become exponential; assuming a private dynamic row issuer, generic WE, online signer, or after-check is not a construction. No PR comment, notification, release or automation-stop claim is justified.
