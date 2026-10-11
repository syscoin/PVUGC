#!/usr/bin/env python3
"""Run 133 deterministic checks for the static early-key extraction boundary.

These are finite probability/algebra/interface checks. They do not instantiate a
witness PRF, prove LWE/SIS hardness, or prove QPT extractability.
"""
from fractions import Fraction
import json, random

SEED = 13320260926
ASSERTIONS = 0

def ck(x):
    global ASSERTIONS
    ASSERTIONS += 1
    assert x


def recovery_to_distinguishing_exact(Q, rows):
    """rows is a joint distribution over (f, yhat) as integer counts.

    The real challenge is f. The random challenge is independent uniform in [Q].
    The compare distinguisher accepts iff yhat equals the challenge.
    """
    total = sum(c for _, _, c in rows)
    rec = Fraction(sum(c for f,y,c in rows if f == y), total)
    # Exact exhaustive random-challenge match probability.
    rnd_num = 0
    for f,y,c in rows:
        for z in range(Q):
            rnd_num += c * int(y == z)
    rnd = Fraction(rnd_num, total * Q)
    ck(rnd == Fraction(1,Q))
    adv = rec - rnd
    ck(adv == rec - Fraction(1,Q))
    return rec, rnd, adv


def random_joint(Q, n, rng):
    rows=[]
    for _ in range(n):
        f=rng.randrange(Q)
        # Mixture of exact recovery, structured wrong guess, and random guess.
        mode=rng.randrange(5)
        if mode in (0,1): y=f
        elif mode==2: y=(f+1)%Q
        else: y=rng.randrange(Q)
        rows.append((f,y,1+rng.randrange(7)))
    return rows


def all_witness_same_key_fixture():
    # One fixed true statement with three valid witnesses and one invalid string.
    valid={"w0","w1","w2"}; F=173
    def Eval(w):
        if w not in valid: return None
        return F
    for w in valid: ck(Eval(w)==F)
    ck(Eval("bad") is None)
    return {"valid_witnesses":len(valid),"common_value":F}


def static_vs_key_correlated_aux(Q):
    # Static auxiliary information is fixed before the fresh key value f.
    # For a fixed aux a, guessing f succeeds exactly 1/Q under uniform f.
    a=0
    static_hits=sum(int(a==f) for f in range(Q))
    ck(static_hits==1)
    # Key-correlated (semi-static/adaptive) auxiliary info can simply be f.
    correlated_hits=sum(int(f==f) for f in range(Q))
    ck(correlated_hits==Q)
    return {
        "range":Q,
        "static_fixed_aux_recovery":str(Fraction(static_hits,Q)),
        "key_correlated_aux_recovery":str(Fraction(correlated_hits,Q)),
    }


def soundness_not_knowledge_fixture():
    # A proof verifier can be perfectly sound for false statements while an
    # accepting proof on a true statement contains no source-witness data.
    # This is only a logical interface counterexample, not a hard language.
    source={"x_true":{"alice","bob"}, "x_false":set()}
    def proof_verify(x,pi):
        return x=="x_true" and pi=="OK"
    ck(proof_verify("x_true","OK"))
    ck(not proof_verify("x_false","OK"))
    # Same proof for two distinct source witnesses: proof soundness supplies no
    # canonical inverse from proof to the original witness that was used.
    pi_from={w:"OK" for w in source["x_true"]}
    ck(len(set(pi_from.values()))==1)
    ck(len(source["x_true"])==2)
    return {"accepted_true_proof":"OK","source_witness_count":2,"false_accepts":False}


def main():
    rng=random.Random(SEED)
    advantage_rows=[]
    for Q in (2,3,5,7,11,17,257):
        # Exhaustive deterministic channels yhat=f and yhat=f+1.
        for kind in ("perfect","shift"):
            rows=[]
            for f in range(Q):
                y=f if kind=="perfect" else (f+1)%Q
                rows.append((f,y,1))
            rec,rnd,adv=recovery_to_distinguishing_exact(Q,rows)
            if kind=="perfect":
                ck(rec==1 and adv==1-Fraction(1,Q))
            else:
                ck(rec==0 and adv==-Fraction(1,Q))
        # Random weighted channels.
        for _ in range(40):
            rec,rnd,adv=recovery_to_distinguishing_exact(Q,random_joint(Q,35,rng))
            advantage_rows.append((Q,float(rec),float(rnd),float(adv)))

    same=all_witness_same_key_fixture()
    aux=[static_vs_key_correlated_aux(Q) for Q in (2,16,256,65536)]
    chain=soundness_not_knowledge_fixture()

    # For lambda-bit output, the comparison loss is exactly 2^-lambda.
    loss={str(lam):2.0**(-lam) for lam in (32,64,128,192,256)}
    ck(loss["128"] < 3e-39)

    out={
        "run":133,
        "seed":SEED,
        "assertions":ASSERTIONS,
        "recovery_to_distinguishing":{
            "random_weighted_channels_checked":len(advantage_rows),
            "identity":"Adv_compare = Pr[recover exact F] - 1/|Y|",
            "lambda_bit_uniform_challenge_loss":loss,
        },
        "all_witness_same_key_fixture":same,
        "static_vs_key_correlated_aux":aux,
        "soundness_not_source_knowledge_fixture":chain,
        "scope":"finite probability and interface identities only; no WPRF/WE/LWE/SIS/QPT security theorem is established by this checker"
    }
    print(json.dumps(out,sort_keys=True,separators=(',',':')))

if __name__=='__main__': main()
