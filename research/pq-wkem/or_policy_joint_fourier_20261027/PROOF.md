# Same-key OR-policy Fourier release: full-joint quantum extraction

Research-only, 2026-10-27. Extends pinned PVUGC #1 Fourier recovery proof (blob d68b015397f46caf30d579bff12220ad04e94d7c), polar release (blob 039e2706200aaf8cb6cf0a2bd9e0d730684abda5), and selector-span sampler (blob 0ae1aaf2d580e37d8332871245b49df3369b5d23). Starting PR head 4e72c613bdc1f624eb2d40bc40c309edc92f2a3e. No new polynomial-rate generic NP construction is claimed.

## The missing composition actually closed

The prior extractor covered one ORIGINAL source, or multiple same-source views. This record proves a *joint* full-public key-recovery/native-forgery-to-ORIGINAL extractor for polynomially many DIFFERENT ORIGINAL relations sharing a native seed, if and only if the policy is a typed **authorized OR** for one claim and one immutable native spending authority. It also permits every source circuit to be derived from the ACTUAL native checking key through a public efficiently simulatable function. No common witness, canonical witness, shared intermediate state, online committee, assumed SourceOpen, random oracle programming, generic-group model, or independent-work-hiding assumption is used.

This is a real scope extension: a quantum adversary may process all capsules simultaneously and exploit their common secret and public checking key, yet extraction produces (branch_id, verified ORIGINAL witness) for at least one AUTHORIZED disjunct. It is not permissible to reuse that native seed for separate UTXOs, independently authorized transactions, or another policy; opening an easier source would compromise all those other uses.

## Source and release algorithms

Let NativeGen sample uniform native signing seed K of k bits and compute its real pk(K), using the native distribution. Let public Policy(pk,claim,context) deterministically create m=poly(lambda) distinct typed ORIGINAL relations R_i(x_i,w_i) BEFORE any release dither/noise is drawn. Relation identity, claim/UTXO, expected native pk, branch and intended message/path scope, chain anchors/window and relevant authorizations are committed. Policy may depend on public pk but not unexposed K or any private coins. All policy input/context/auxiliary fields must be simulated given pk by the native challenger; this is an independently checkable distributional precondition, not guaranteed when external history is correlated with unknown native secret material.

For each x_i, the established SOURCE compiler outputs homogeneous C_i, public full row basis B_i of ker(C_i), shift b_i=B_i e0 and a classical physical mask E_i. Define P_{i,z}=Law(B_i E_i+b_i z) on its ENTIRE public quotient, z in {0,1}. Each accepted Fourier character a satisfies v=a^T B_i, v0=1 and efficiently and unambiguously yields a verified ORIGINAL witness (not a private verifier surrogate). Let S_i be this set and s_i its cardinality. Require the previously established entire-distribution identity:

    Fourier(P_{i,1})(a)-Fourier(P_{i,0})(a)
      = -2 rho_i for a in S_i, and zero otherwise.

For every false ORIGINAL x_i, S_i is empty, so P_{i,1}=P_{i,0} EXACTLY. A new physical sampler cannot be substituted without proving this identity.

Build: sample K, real pk, Policy and independent public uniform k-bit dithers D_i. For branch i choose a predetermined public binary code Enc_i:{0,1}^k->{0,1}^{N_i} with a certified decoder. Let U_i=K XOR D_i and c_i=Enc_i(U_i). Independently sample physical errors E_{i,j}, publishing Q_{i,j}=B_i E_{i,j}+b_i c_i[j] for each 1<=j<=N_i. Publish every x_i,C_i,B_i,code,D_i,Q_i, real pk, claim and anchor context, permissible pre-signatures/auxiliary inputs and related capsules in ONE joint view. Honest setup/erasure are assumed as in the predecessor; this is not an implemented malicious N-of-N ceremony or keyless Build.

Recover(i,w_i): verify the ORIGINAL R_i(x_i,w_i) OFF CHAIN. Convert its normalized one-hot mode into a_i with a_i^T B_i=v_i^T. For each j calculate y_j=a_i^T Q_{i,j}=c_i[j]+v_i^T E_{i,j}. For fixed accepted w_i, independent columns form BSC((1-rho_i)/2); its own decoder recovers U_i, then K=U_i XOR D_i. Compare the real pk and locally sign only an authorized challenge-path message. Distinct witnesses and branches may have different SOURCE representations and noisy intermediate observations but decode the SAME precommitted native K when decoding succeeds. The public D_i makes information bits uniform conditional on any fixed K and real pk(K), so per-witness polar error certificates apply.

For any branch i, if epsilon_i is its certified per-witness decoder failure and M_i is a proven upper bound on distinct accepted projected physical-noise functions, simultaneous correctness obeys Pr[any accepted branch witness fails] <= sum_i M_i epsilon_i. For deterministic t_i-bit SOURCE, M_i<=2^t_i; the previously proved physical error-image rank may tighten M_i<=2^min(t_i,r_E_i) when applicable. Neither Build nor Recover enumerates the witnesses.

## Exact false OR-policy whole-public security

If every R_i is false, every P_{i,1}=P_{i,0}. Even though the c_i share exactly the same K and are correlated with real pk, condition on any K,pk,Policy and public D_i: the full JOINT law of all Q columns equals product over i,j of P_{i,0}. Hence the native-null simulator given only the ACTUAL pk samples Policy(pk,...), all dithers and independently sampled B_i E_{i,j} (no private K). The native pk, native signing oracle/pre-signed material and all allowed context remain in the view; to include secret-dependent fields, the native game must explicitly supply a matching simulation. Thus for the precisely matched all-false game, real key-recovery/fresh-forgery probabilities equal those of the native null experiment. No per-column argument is substituted for this joint equality. QPT postprocessing does not distinguish identical classical-quantum distributions under the declared auxiliary independence premise.

If any R_i is true, this all-false security statement does not apply: opening that AUTHORIZED disjunct intentionally releases K. Sharing K with an unrelated false claim is categorically unsafe.

## Coherent multi-branch extraction, with exact weights

Let A be any arbitrary QPT algorithm receiving the whole correlated package, seeking exact K or an actually fresh accepted native signature. Coherent access to a reversible implementation A, its inverse and the appropriate success check (exact K in the extractor's generated-key game, public fresh signature verifier otherwise), plus ONE allowed quantum advice state independent of fresh release noise, is the predecessor's stated access model. No classical rewinding, oracle-programmed hash extraction, cloning or attacker-volunteered SOURCE representation is assumed. Native signing/preauthorization interaction must be reversible/simulatable to the extent needed by this stronger extractor; an already approved transaction edge is not a fresh forgery.

Order all N_total=sum_i N_i release columns. Define hybrids G_h by replacing the first h columns, successively, with independently sampled P_{i,0} while retaining the real common K, real pk, ALL branch source descriptions, public dithers, all unmodified columns and all declared native/auxiliary challenge inputs. G_0 is actual Build and G_Ntotal is the exact native-null view. The source circuits may depend on public pk, because pk is fixed while each particular column is varied; both the extraction game generating K and the native-null game receiving pk can compute the same Policy(pk,...). The conditional success function f_h(y) of an arbitrary full-view quantum A is defined over only the selected column's complete quotient y.

The predecessor's success-phase reflection and Fourier measurement, using the full identity above, return a valid ORIGINAL witness of branch i with conditional probability at least gap_h^2/(s_i rho_i^2) whenever its hybrid success gap is gap_h, with zero gap for c_i[j]=0 or S_i empty. Average over the other setup/key/auxiliary coins and apply Jensen; if q_h is the actual per-position extractor success and Delta_h its mean signed hybrid gap:

    |Delta_h| <= rho_i sqrt(s_i) sqrt(q_h).

Choose public constant a_h>=rho_i sqrt(s_i), valid for EVERY policy-generated pk/context, without computing an NP witness. Deterministic bounds rho_i sqrt(bar_s_i), possibly maximized over permitted public configurations, suffice. Let W=sum_h a_h; sample a hybrid position with probability pi_h=a_h/W. Define p_Ext as this ONE coherent weighted extractor's overall probability of outputting a verified pair (branch_id, ORIGINAL witness).

Telescoping and weighted Cauchy-Schwarz give

    p_real - p_null = sum_h Delta_h
      <= sum_h a_h sqrt(q_h)
      <= W sqrt(sum_h pi_h q_h)
      = W sqrt(p_Ext).

The native null simulator receives the real pk challenge, computes every x_i from that pk, samples every public D_i and P_{i,0} and simulates all permitted aux. It NEVER needs the native secret. Thus p_null=p_native in the exact native key recovery or fresh EUF-CMA game:

    p_real <= p_native + W sqrt(p_Ext).
    p_Ext >= max(0,p_real-p_native)^2/W^2.

With fixed branch parameters W=sum_i N_i rho_i sqrt(bar_s_i). The QPT extractor uses one coherent A execution/inverse and SOURCE verification, with actual full-transcript size included in its time and quantum-query budget. A theorem polynomial in that emitted length is not automatically polynomial in source/circuit size.

This proof covers DIFFERENT true source circuits and same-K public correlation for a single authorized OR policy. It does not prove arbitrary same-key selective openings, secret-dependent SOURCE generation, target error-mask exposure, malicious setup aborts or a native Bitcoin PQ transaction graph.

## Binding work and arbitrary NP without substituting a weak work claim

Suppose EACH accepted branch witness (i,w_i) projects by an efficient publicly checked algorithm Proj_i to a winning event in an independently defined resource-matched work game Work_OR(claim,pk,history). The extraction algorithm composes with Proj_i; if that game bounds quantum success by delta_work(B_star), where B_star includes coherent A/A^-1, public history, pre-mining and all oracle resources, then

    p_real <= p_native + W sqrt(delta_work(B_star)).

This does not assume a witness PRF, or that PoW validates an arbitrary NP condition: the source compiler's exact false-instance hiding enforces all attached NP gates. The work bound is independent and still must be established.

A claim whose OR policy contains quick authenticated broken-tag/incompatible-fork veto evidence must use Work_OR including THAT event. It is mathematically invalid to bound it solely by the cost of independently mining 100 BTC blocks. Comparable higher-work branches are different. An existing publicly known accepted 100-block history may make the witness-search probability one. The actual bridge would have to compile and verify headers, AuxPoW, tagged coinbases, direction/lag, Merkle proofs, authenticated ancestor links and every relevant interval tag; no such full compiler or Bitcoin quantum work bound was executed here. The no-EC native output, PQ signature endpoint, N-of-N presigning/erasure, data availability, aborts and Bitcoin graph remain conditional and unproved.

## Evidence and next exact obligation

The self-contained exact checker enumerates ALL 65,536 deterministic joint success predicates f(y1,y2) for two different true Fourier modes sharing one key. It checks complete quotient Fourier laws, same-key false-native-pk-conditioned full distributions, the two-step full-public hybrid telescope and the actual one-reflection Fourier extraction inequality for every f (tight in one case). Two deterministic executions were byte identical. This is finite algebra and a special reversible strategy class, NOT a proof of arbitrary QPT hardness, no-attack-found, or an actual Bitcoin/Syscoin verifier.

The next central equation is STILL missing for practical generic NP: a classically efficient polynomial-rate SOURCE-dependent release whose entire public distribution is simulatable from an independently justified QPT reduction and whose unauthorized full-key recovery implies the ORIGINAL witness or a standard-PQ break with nonvacuous resource accounting. These typed OR and public-key-binding composition lemmas narrow its required interface but do not replace it.