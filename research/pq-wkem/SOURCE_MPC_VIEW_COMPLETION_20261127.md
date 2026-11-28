# Source-dependent MPC view completion and a terminal-tape release attempt — 2026-11-27 UTC

Nonqualifying research iteration. No secure WKEM, deployment recommendation, or new source-consensus claim.

## Continuity and selection

Actual start: syscoin/PVUGC PR #1, open/draft/unmerged, head repository syscoin/PVUGC, branch research/pq-wkem-validation-20260918, SHA a6d1c6da88ad221e0ab6efee312337cfaf6841de. Read actual PR metadata, recent substantive discussion (through R225), exact head commit metadata and its SOURCE_FULL_ADDRESS_FSS_LATE_MERGE_20261127.md, blob 1ca67263d1fbfc822f28a7f67d9aa9fe1704c7ab. Duplicate check for this path returned NOT_FOUND/404. Prewrite metadata still had the same head.

Missing operation: produce one offline public capsule before the future original witnesses are known, with a source-authentication-dependent path from EVERY qualifying original certificate to the SAME precommitted native cancellation capability, plus a full-public QPT argument. Let V(x,w) be the COMPLETE original claim-bound relation, including the three independent OR grounds, not a substituted easier relation. Its bounded deterministic classical verifier can be expressed as a Boolean circuit, or an arithmetic circuit over an odd prime field using Boolean gates and checks, with result z=V(x,w) in {0,1}. This is an abstract circuit compilation, not a new implementation or audit of the actual Core verifier.

Selection: move away from the previous independent terminal hash correction and R289's split masks. Attempt **source-dependent completion of a single public, simulated MPC view**, with the payload carried by a hidden dealer's resharing tape. Explicit mathematical change: interpolate missing shares from the ENTIRE original witness and the fixed opened view, and reconstruct all hidden messages in the same execution, rather than release independent reusable labels per wire or locally compute an opposite terminal hash pad. This supplies a concrete witness-dependent transcript operation (no ideal evaluator, no independent terminal hash correction). Check whether embedding a fixed secret in the completion survives the joint public view. The field is only an arithmetic protocol; there is no discrete-log, lattice, or other algebraic hardness assumption.

## 1. Actual polynomial BuildView and CompleteView

Work over F_p for p>3, with party coordinates 1,2,3. For a secret wire value u the sharing polynomial is f_u(T)=u+r_u T. Public constants have constant polynomials. A full opened view for party 1 includes its input shares, its outgoing randomness, and all incoming multiplication messages. Addition/subtraction is local.

At each multiplication gate g with input shares a_i,b_i, party i computes p_i=a_i b_i and samples a fresh uniform slope rho_i. It sends m_{i,j}=p_i+j rho_i to party j. The output sharing is

    f_g(T)=3(p_1+rho_1 T)-3(p_2+rho_2 T)+(p_3+rho_3 T).

The constants (3,-3,1) interpolate a polynomial of degree <=2 at zero from points 1,2,3. Consequently f_g(0)=ab and f_g has degree <=1.

BuildView (no witness):
* Sample the opened party's share of each private witness input uniformly; x and public constants are fixed.
* Process the circuit in topological order. At multiplication g, compute p_1 from its known input shares, sample rho_1,m_{2,1},m_{3,1} independently uniformly, set m_{1,1}=p_1+rho_1, and set the opened output share to 3m_{1,1}-3m_{2,1}+m_{3,1}. Serialize the input shares, rho_1 and the two incoming messages for every multiplication. Everything else is deterministic.

For ANY fixed input w, this is EXACTLY the joint distribution of the opened party's view in the real honest protocol, before any optional claimed-output reconstruction: conditional on the whole earlier execution, p_i is fixed and rho_i is fresh independent uniform, so m_{i,1}=p_i+rho_i is fresh uniform for hidden parties. This holds gate by gate, not merely for marginal labels. If the protocol includes public reconstruction of z, then for z=1 the other two output shares are 2-z_1 and 3-2z_1, entirely determined by the opened view. The same simulator appends these for all valid w. It does not simulate a real accepting view for an invalid w.

CompleteView (public, with proposed w):
* Recover all input sharing polynomials from the secret input values and opened shares: f_u(T)=u+(u_1-u)T.
* Process the circuit in order. At each multiplication compute all p_i from the reconstructed predecessor polynomials, set rho_i=m_{i,1}-p_i for i=2,3, and reconstruct all outgoing messages and f_g by the formula above. Party 1's slope is already serialized.
* Check any claimed output reconstruction against the completed sharing.

Inductively this produces the UNIQUE complete consistent transcript for that w and fixed opened view; at every gate both the original wire value and opened share agree. In particular every original valid w completes an accepting transcript. Invalid w also completes a consistent arithmetic execution, with its actual invalid output, rather than being cryptographically prevented from obtaining internal tape values. This is a real classical-PPT witness-dependent operation, but it does not yet release a secret. There is no hidden simulator state required by CompleteView.

## 2. Concrete Build/Open payload embedding and full-public failure

Append an extra multiplication gate z times 1 (output still z). For an accepting original witness, the hidden party 2 share of z is z_2=2-z_1, and the public constant 1 has share 1. Thus its local product at this gate is p_2^*=2-z_1. Build can calculate this from the serialized prefix WITHOUT knowing any valid witness.

Choose K uniformly in F_p, with p of adequate cryptographic size, and run BuildView for the complete original verifier. At the extra gate choose m_{2,1}=K+(2-z_1) instead of an independent uniform message. Other randomness as before. This keeps the opened view's EXACT marginal distribution unchanged because K is uniform independently of the prefix. Output that view and E=sigma_cancel XOR H_final(ctx,enc(K)), with domain-separated length expansion for the native capability. This is the attempted actual Build, not an oracle; ctx is the complete capsule/claim/native endpoint binding. No native signature implementation is claimed.

Public Open performs CompleteView on original w, requires the accepting output, obtains rho_2 from the extra gate, and unmasks E. For every qualifying ORIGINAL w, rho_2=m_{2,1}-(2-z_1)=K, so every such w yields exactly sigma_cancel. There is no chosen canonical w, no need to predict its hidden shares, and no cross-witness label mixing. Build/Open are classical PPT in the original verifier circuit size.

But this also gives the attack directly from the FULL serialized public view:

    K = m_{2,1} - 2 + z_1.

The attacker computes z_1 by the public BuildView prefix recurrence, not by completing a valid original witness. This works on FALSE and hard-TRUE statements alike, with no source certificate, oracle inversion, trace from an arbitrary adversary, or native forgery assumption. The attack recovers the EXACT capability, hence does not rely on conflating same-message forgery and exact recovery. If it runs honest CompleteView on an invalid w with z=0 instead, that completion yields rho_2=K+2, also trivially convertible to K. The accept check is only an honest-code branch. An independent marginal simulator for the public view does not simulate its joint correlation with E. For example on a challenge with known candidate payloads, the real view identifies the correct candidate via the displayed equation; an independent uniform key used for E would not have that same correlation.

This is distinct from the last head's independent terminal correction: no fresh address, no hidden opposite PRF, no terminal query logging. The failure is a **publicly reconstructible interpolation invariant**, even though the full original witness really does enable consistent transcript reconstruction.

## 3. Repair attempt: leave extra hidden degrees of freedom in the transcript

Try degree t Shamir sharing with n=2t+1 parties at distinct nonzero coordinates over F_p, p>n, and only k<t complete public views. Use the same resharing multiplication with degree-t dealer polynomials and nonzero degree-2t interpolation weights lambda_i. The intended change is to put K into a hidden resharing coefficient NOT determined by known output z and the opened shares, so the section 2 attack no longer computes it by interpolation.

For fixed w and fixed opened views, however, the hidden dealer's degree-t polynomial is constrained only at zero (its local product) and k opened coordinates. It has t-k free coefficients. This is not only a count: at the last multiplication let S be the opened coordinates, and

    L(T)=T product_{j in S}(T-j).

It has degree k+1<=t. Choose two hidden dealers i,h (there are at least two). Add alpha L(T) to dealer i and subtract (lambda_i/lambda_h) alpha L(T) from dealer h. Both constants, all opened messages, and the ENTIRE final output sharing polynomial remain exactly unchanged. Hence even publishing all final output reconstruction shares does not remove this free direction. The same valid ORIGINAL w completes each of these different hidden dealer tapes. For an honestly uniform free coefficient, the affine shift is a bijection of the consistent transcript fiber. Thus the full original witness and consistency alone no longer determine a hidden tape coefficient along this direction. A hash commitment to that chosen coefficient would bind a particular value, but the witness does not determine which value to open; a separate method deriving that opening from original evidence is required. This is not a general lower bound against a nontrivial additional correlated public capsule.

One could reuse a hidden slope across two gates in the degree-one completion to couple the free choices to the witness, instead of adding a commitment to an independent puzzle. For gates g,h with true wire inputs a,b and c,d, respectively, the exact consistency equation at hidden party 2 is

    m_{2,1}^g - m_{2,1}^h
      = (2a-a_1)(2b-b_1) - (2c-c_1)(2d-d_1).

Build would have to choose the same left side before knowing any w, for ALL accepting original executions. Choosing gates with a public local accepting-output identity gives a known local assignment to compute the shared tape, as in section 2; choosing arbitrary gates with differing valid witness values generally breaks every-witness completeness. We have not found a nonlocal correlation for the actual V which makes the equation hold for every original witness while keeping a tape component secret from the serialized view. This is the concrete outstanding operation for this repair, not a new coefficient/rank/parameter search. Do not assume a hidden MPC party or an online party to impose the correlation.

The threshold change therefore removes the specific local interpolation attack on an individual free coefficient but also removes the unique source-dependent completion needed for release. The actual payload-bearing protocol and full-public simulator have not been repaired. A future approach using this paradigm must supply a **witness-determined but publicly hidden selection of a completion fiber**, with an explicit witnessless classical-PPT sampler of its correlated public view and a joint QPT simulator including E and native context. Merely committing to a hidden view, programming a private proof simulator, or hashing complete witness-dependent transcripts does not implement that selection; distinct original witnesses need not produce identical transcripts or hashes. No primitive promising the desired common-value selection is assumed.

## Scope and actions

This is a failed construction/repair, not a qualifying update. No source maturity, tag, or Core behavior is changed or newly claimed; no deployment claim. All original OR grounds, R225 endpoint scope, R316 correction, malicious N-of-N setup/erasure and useful completeness, multi-capsule/auxiliary correlations, native endpoint, and deadline/inclusion obligations remain intact. The transcript distribution proof above is exact classical arithmetic, not a QPT theorem about the required WKEM. No code, test, subagent, web, or external literature was invoked; static derivation only. GitHub actions: metadata, recent relevant substantive discussion, exact head commit/file read, duplicate path check, prewrite head check; no ordinary PR progress comment.
