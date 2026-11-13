#!/usr/bin/env python3
"""
Run 152 deterministic checker.

Finite algebra/probability validation for a CMV-style MinRank capsule compiled
from an affine Hair--Sahai source slice.

What it checks:
1. Public affine source slice U + span(K_i) with multiple rank-one witnesses.
2. Every rank-one MinRank witness decrypts the SAME bit-0 CMV-style capsule.
3. Complete ciphertext Fourier law for a sum-of-r rank-one randomizer:
      E[(-1)^<Lambda,C>] = 2^(-r * rank(N_Lambda)).
4. False-source gap transfer: every nonzero character on a tiny false source
   has N_Lambda rank >= D.
5. Exact false transcript TV against uniform and its Fourier/chi-square identity.
6. A toy low-rank response character illustrating the one-copy Fourier
   extraction interface: predictor advantage is carried by a source-bearing
   low-rank character.
7. Exact random-matrix low-rank probability for small t and a conservative
   rank-deficiency bound.

This checker DOES NOT prove MinRank hardness, Hair--Sahai security, QPT security,
or a complete witness KEM.  It uses tiny F_2 fixtures and exhaustive enumeration.
"""
from __future__ import annotations
import itertools, json
from collections import Counter
from fractions import Fraction

def madd(A,B):
    return tuple(tuple(a^b for a,b in zip(ra,rb)) for ra,rb in zip(A,B))

def mzero(r,c):
    return tuple(tuple(0 for _ in range(c)) for _ in range(r))

def smul(bit,A):
    return A if bit else mzero(len(A),len(A[0]))

def msum(ms):
    ms=list(ms)
    if not ms:
        return ()
    out=mzero(len(ms[0]),len(ms[0][0]))
    for M in ms:
        out=madd(out,M)
    return out

def rank2(A):
    A=[list(row) for row in A]
    if not A: return 0
    m=len(A); n=len(A[0]); r=0
    for c in range(n):
        piv=None
        for i in range(r,m):
            if A[i][c]:
                piv=i; break
        if piv is None: continue
        A[r],A[piv]=A[piv],A[r]
        for i in range(m):
            if i!=r and A[i][c]:
                A[i]=[x^y for x,y in zip(A[i],A[r])]
        r+=1
        if r==m: break
    return r

def outer(u,v):
    return tuple(tuple(a&b for b in v) for a in u)

def kron(A,B):
    return tuple(
        tuple(A[i][j] & B[ii][jj]
              for j in range(len(A[0])) for jj in range(len(B[0])))
        for i in range(len(A)) for ii in range(len(B))
    )

def block_ip(R,A,t):
    n=len(R); assert n%t==0 and len(A)==n
    b=n//t
    out=[]
    for p in range(t):
        row=[]
        for q in range(t):
            s=0
            for i in range(b):
                for j in range(b):
                    s ^= (R[p*b+i][q*b+j] & A[p*b+i][q*b+j])
            row.append(s)
        out.append(tuple(row))
    return tuple(out)

def frob(A,B):
    s=0
    for ra,rb in zip(A,B):
        for a,b in zip(ra,rb):
            s ^= (a&b)
    return s

def encode_matrix(A):
    x=0; bit=0
    for row in A:
        for b in row:
            x |= (b&1)<<bit
            bit+=1
    return x

def decode_matrix(x,r,c):
    out=[]; bit=0
    for _ in range(r):
        row=[]
        for _ in range(c):
            row.append((x>>bit)&1); bit+=1
        out.append(tuple(row))
    return tuple(out)

def encode_tuple(ms):
    x=0; shift=0
    for M in ms:
        e=encode_matrix(M)
        bits=len(M)*len(M[0])
        x |= e<<shift
        shift += bits
    return x

def character(lam_tuple,c_tuple):
    s=0
    for L,C in zip(lam_tuple,c_tuple):
        s ^= frob(L,C)
    return -1 if s else 1

def n_lambda(lams, basis, t):
    # basis = [K1,...,Kd,U], each base m x m.
    m=len(basis[0])
    blocks=[[mzero(m,m) for _ in range(t)] for __ in range(t)]
    for p in range(t):
        for q in range(t):
            acc=mzero(m,m)
            for idx,B in enumerate(basis):
                if lams[idx][p][q]:
                    acc=madd(acc,B)
            blocks[p][q]=acc
    # assemble t x t blocks
    return tuple(
        tuple(blocks[p][q][i][j]
              for q in range(t) for j in range(m))
        for p in range(t) for i in range(m)
    )

def all_vec(n):
    return list(itertools.product((0,1),repeat=n))

def all_mats(r,c):
    return [decode_matrix(x,r,c) for x in range(1<<(r*c))]

def all_rank_one_sum_randomizers(n,r):
    # distribution induced by r independent uniform outer products u v^T
    vecs=all_vec(n)
    counter=Counter()
    for pairs in itertools.product(list(itertools.product(vecs,vecs)), repeat=r):
        R=mzero(n,n)
        for u,v in pairs:
            R=madd(R,outer(u,v))
        counter[encode_matrix(R)] += 1
    return counter

def capsule_distribution(basis, t, r):
    # basis already lifted n x n: [A1,...,Ad,Y]
    n=len(basis[0])
    rc=all_rank_one_sum_randomizers(n,r)
    out=Counter()
    for encR,mult in rc.items():
        R=decode_matrix(encR,n,n)
        C=tuple(block_ip(R,B,t) for B in basis)
        out[encode_tuple(C)] += mult
    total=sum(out.values())
    return out,total

def tv_counter_uniform(counter,total,space_size):
    # exact TV using common denominator total*space_size
    num=0
    for x in range(space_size):
        c=counter.get(x,0)
        num += abs(c*space_size-total)
    return Fraction(num,2*total*space_size)

def fourier_coeff(counter,total,lam_tuple,t,basis_count):
    s=0
    for encC,mult in counter.items():
        # decode tuple of basis_count t x t matrices
        mask=(1<<(t*t))-1
        C=[]
        x=encC
        for _ in range(basis_count):
            C.append(decode_matrix(x&mask,t,t)); x >>= t*t
        s += mult*character(lam_tuple,tuple(C))
    return Fraction(s,total)

def rank_count_square(t,k):
    if k<0 or k>t:
        return 0
    if k==0:
        return 1
    num=1
    den=1
    for i in range(k):
        num *= (2**t-2**i)*(2**t-2**i)
        den *= (2**k-2**i)
    return num//den

def low_rank_uniform_prob(t,r):
    good=sum(rank_count_square(t,k) for k in range(r+1))
    return Fraction(good,2**(t*t))

def main():
    assertions=0
    # YES affine source slice: both U and U+K rank one.
    U=((1,0),(0,0))
    K=((0,1),(0,0))
    assert rank2(U)==1; assertions+=1
    assert rank2(madd(U,K))==1; assertions+=1

    # FALSE affine source slice: every nonzero in span{U_f,K_f} has rank 2.
    Uf=((1,0),(0,1))
    Kf=((0,1),(1,1))
    assert rank2(Uf)==rank2(Kf)==rank2(madd(Uf,Kf))==2; assertions+=1

    t=2; r=1
    J=((1,1),(1,1))

    # Public MinRank basis order = [K,U].
    yes_base=[K,U]
    false_base=[Kf,Uf]
    yes_lift=[kron(J,B) for B in yes_base]
    false_lift=[kron(J,B) for B in false_base]

    # Exact structured ciphertext distributions.
    Pyes,Nyes=capsule_distribution(yes_lift,t,r)
    Pfalse,Nfalse=capsule_distribution(false_lift,t,r)
    assert Nyes==Nfalse==256
    assertions+=1

    # All-witness correctness for bit 0:
    # secret s=0 gives residual U; s=1 gives U+K.
    witness_rank_hist={}
    mask=(1<<(t*t))-1
    for s in (0,1):
        bad=0; hist=Counter()
        for encC,mult in Pyes.items():
            C1=decode_matrix(encC&mask,t,t)
            C2=decode_matrix((encC>>(t*t))&mask,t,t)
            M=madd(C2,smul(s,C1))
            rr=rank2(M); hist[rr]+=mult
            if rr>r: bad+=mult
        assert bad==0; assertions+=1
        witness_rank_hist[str(s)]={str(k):v for k,v in sorted(hist.items())}

    # Uniform bit-1 branch is independent uniform pair of t x t matrices.
    # For either s, M=C2+s*C1 is uniform t x t.
    p_low=low_rank_uniform_prob(t,r)
    assert p_low==Fraction(10,16); assertions+=1

    # Complete Fourier law for every character on the false fixture.
    mats_t=all_mats(t,t)
    false_fourier_checked=0
    false_gap_checked=0
    chi2=Fraction(0,1)
    max_nonzero=Fraction(0,1)
    rank_hist=Counter()
    for L1 in mats_t:
        for L2 in mats_t:
            lams=(L1,L2)
            empirical=fourier_coeff(Pfalse,Nfalse,lams,t,2)
            N=n_lambda(lams,false_base,t)
            rho=rank2(N)
            predicted=Fraction(1,2**(r*rho))
            assert empirical==predicted
            assertions+=1
            false_fourier_checked+=1
            if encode_matrix(L1)!=0 or encode_matrix(L2)!=0:
                assert rho>=2
                assertions+=1
                false_gap_checked+=1
                rank_hist[rho]+=1
                chi2 += empirical*empirical
                if abs(empirical)>max_nonzero: max_nonzero=abs(empirical)

    # Exact chi-square / Parseval identity against uniform.
    # chi^2(P||U) = sum_nonzero hatP^2 in normalized character convention.
    L=2*t*t
    space=1<<L
    chi2_direct=Fraction(0,1)
    for x in range(space):
        p=Fraction(Pfalse.get(x,0),Nfalse)
        u=Fraction(1,space)
        chi2_direct += (p-u)*(p-u)/u
    assert chi2==chi2_direct; assertions+=1

    tv_false=tv_counter_uniform(Pfalse,Nfalse,space)
    # Pins the tiny fixture; high TV demonstrates gap alone isn't enough.
    assert tv_false > Fraction(1,2); assertions+=1

    # TRUE character: choose Lambda only on U slot, one block.
    Z=((0,0),(0,0))
    L2=((1,0),(0,0))
    lam0=(Z,L2)
    N0=n_lambda(lam0,yes_base,t)
    assert rank2(N0)==1; assertions+=1
    coeff0=fourier_coeff(Pyes,Nyes,lam0,t,2)
    assert coeff0==Fraction(1,2); assertions+=1

    # Toy deterministic predictor response f(C)=chi_lam0(C):
    # E_P0 f = 1/2, E_U f = 0.
    # In equal-prior bit prediction, success = 1/2 + gap/4 = 5/8.
    predictor_success=Fraction(1,2)+coeff0/Fraction(4,1)
    assert predictor_success==Fraction(5,8); assertions+=1

    # Its normalized Fourier spectrum is a point mass at lam0, so a coherent
    # Fourier sampler would return that low-rank source-bearing frequency.
    # Check the nonzero block maps back to U, hence to witness s=0.
    assert N0[:2] != mzero(2,4)  # structural nonzero sanity
    assertions+=1
    # Directly inspect blocks: only (0,0) equals U.
    # n_lambda layout 4x4, top-left 2x2 block:
    blk=tuple(tuple(N0[i][j] for j in range(2)) for i in range(2))
    assert blk==U; assertions+=1
    assert rank2(blk)==1; assertions+=1

    # Random matrix deficiency ledger, with conservative 4*2^{-(t-r)^2} bound.
    deficiency={}
    for tt in range(2,6):
        for rr in range(0,tt):
            p=low_rank_uniform_prob(tt,rr)
            bound=Fraction(4,2**((tt-rr)**2))
            # bound can exceed 1; probability is trivially <= min(1,bound)
            assert p <= min(Fraction(1,1),bound)
            assertions+=1
            deficiency[f"t={tt},r={rr}"]={
                "prob_rank_le_r":[p.numerator,p.denominator],
                "bound_4x":[bound.numerator,bound.denominator],
            }

    out={
      "status":"PASS",
      "identifier":"RUN152_CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE",
      "assertions":assertions,
      "fixture":{
        "field":"F2",
        "t":t,
        "randomizer_outer_products":r,
        "randomizer_factor_pairs":Nyes,
        "yes_witness_rank_hist":witness_rank_hist,
        "uniform_bit1_prob_rank_le_1":[p_low.numerator,p_low.denominator],
      },
      "false_complete_fourier":{
        "characters_checked":false_fourier_checked,
        "nonzero_gap_characters":false_gap_checked,
        "rank_histogram":{str(k):v for k,v in sorted(rank_hist.items())},
        "max_nonzero_fourier":[max_nonzero.numerator,max_nonzero.denominator],
        "chi_square":[chi2.numerator,chi2.denominator],
        "tv_structured_vs_uniform":[tv_false.numerator,tv_false.denominator],
      },
      "toy_qpt_extraction_interface":{
        "source_frequency_rank":rank2(N0),
        "structured_response_correlation":[coeff0.numerator,coeff0.denominator],
        "equal_prior_prediction_success":[predictor_success.numerator,predictor_success.denominator],
        "source_block_rank":rank2(blk),
      },
      "random_matrix_deficiency":deficiency,
      "scope":[
        "All-witness correctness and Fourier identities only on finite fixtures.",
        "No MinRank hardness or Hair-Sahai encryption theorem is imported.",
        "No QPT theorem is proved by this checker; the note gives the circuit/Fourier reduction.",
        "The randomizer distribution is a sum of uniform rank-one outer products, chosen for an exact Fourier law; it is not CMV's exact uniform-rank<=r sampling.",
        "The tiny bit-1 correctness probability is not a cryptographic parameter set.",
        "The false tiny fixture is deliberately far from hiding."
      ]
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
