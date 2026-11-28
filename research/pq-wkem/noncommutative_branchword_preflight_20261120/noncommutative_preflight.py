#!/usr/bin/env python3
"""Synthetic public conjugated branching program. This is not witness encryption.

One-bit FALSE gadget x AND not-x and a two-bit TRUE gadget x AND y.
Public masked branch matrices include no private U_i. Attacker reconstructs
start gauge using simultaneous permutation conjugacy, recovers secret on FALSE.
All secrets are synthetic and deterministic. No Bitcoin/source material.
"""
import random,hashlib,json
ID=lambda n:tuple(range(n))
def mul(a,b):return tuple(a[b[i]] for i in range(len(a)))
def inv(a):return tuple(a.index(i) for i in range(len(a)))
def powp(a,k):
    if k<0: return powp(inv(a),-k)
    t=ID(len(a))
    for _ in range(k): t=mul(t,a)
    return t

def mask(t, sid):return hashlib.sha256(b'NC1/GROUP/MASK'+sid+bytes(t)).digest()
def xor(a,b):return bytes(i^j for i,j in zip(a,b))

def recover_conjugators(D,Q):
    """Find U with D_i U = U Q_i. Transitive multi-generator set.
    This is graph propagation, not brute-force over n! hidden permutations.
    """
    n=len(D[0]); options=[]
    for image0 in range(n):
        known={0:image0}; queue=[0]; good=True
        for p in queue:
            for d,q in zip(D,Q):
                pn=q[p]; im=d[known[p]]
                if pn in known:
                    if known[pn]!=im:good=False;break
                else:
                    if im in known.values():good=False;break
                    known[pn]=im;queue.append(pn)
            if not good:break
        if good and len(known)==n:
            u=tuple(known[i] for i in range(n))
            if all(mul(d,u)==mul(u,q) for d,q in zip(D,Q)):
                options.append(u)
    return options

def test(n,false,seed):
    rng=random.Random(seed); identity=ID(n)
    a=tuple((i+1)%n for i in range(n))
    # b is transposition; [a,b] is nonidentity
    b=list(identity);b[0],b[1]=b[1],b[0];b=tuple(b)
    c=mul(mul(mul(a,b),inv(a)),inv(b));assert c!=identity
    if false:
        # x AND (!x) is FALSE. Four branch factors, all use SAME x.
        selectors=[lambda x:x,lambda x:1-x,lambda x:x,lambda x:1-x]
    else:
        # TRUE: x AND y
        selectors=[lambda x,y:x,lambda x,y:y,lambda x,y:x,lambda x,y:y]
    factors=[a,b,inv(a),inv(b)]
    g=[]
    for j,factor in enumerate(factors):
        p=[]
        for s in (0,1):
            v=selectors[j](s) if false else s
            p.append(factor if v else identity)
        g.append(p)
    gauges=[]
    for j in range(5):
        p=list(identity);rng.shuffle(p);gauges.append(tuple(p))
    # Only C rows are exposed. Private gauges are not used in extraction.
    rows=[ [mul(mul(inv(gauges[j]),g[j][s]),gauges[j+1])
           for s in (0,1)] for j in range(4)]
    p0=identity;prefixes=[]
    for j in range(4):
        prefixes.append(p0);p0=mul(p0,rows[j][0])
    d0=identity;D=[];Q=[]
    for j in range(4):
        delta=mul(g[j][1],inv(g[j][0]))
        D.append(mul(mul(d0,delta),inv(d0)))
        ratio=mul(rows[j][1],inv(rows[j][0]))
        Q.append(mul(mul(prefixes[j],ratio),inv(prefixes[j])))
        d0=mul(d0,g[j][0])
    opts=recover_conjugators(D,Q)
    assert gauges[0] in opts
    # All-zero row product may have nonidentity unmasked interior G0.
    G0=d0
    # p0 = U0^-1 G0 U4. So U4= G0^-1 U0 p0.
    sid=hashlib.sha256(f'NC1-TEST-{n}-{false}'.encode()).digest()
    secret=hashlib.sha256(b'synthetic unpublished cancel capability'+sid).digest()
    t1=mul(mul(inv(gauges[0]),c),gauges[4])
    encrypted=xor(secret,mask(t1,sid))
    recovered=[]
    for u0 in opts:
        ul=mul(mul(inv(G0),u0),p0)
        candidate=xor(encrypted,mask(mul(mul(inv(u0),c),ul),sid))
        recovered.append(candidate)
    assert secret in recovered
    # For the FALSE x AND not-x word: Q_1=U0^-1 a U0 and
    # Q_4=U0^-1 b U0; their public commutator is U0^-1 c U0.
    # Also G0=identity, hence P0=U0^-1 U4. No gauge solving needed.
    direct_public_word_recovery=False
    if false:
        assert G0==identity
        q_a=Q[0];q_b=Q[3]
        public_c=mul(mul(mul(q_a,q_b),inv(q_a)),inv(q_b))
        public_target=mul(public_c,p0)
        assert public_target==t1
        assert xor(encrypted,mask(public_target,sid))==secret
        direct_public_word_recovery=True
    # Honest Open by complete prescribed input. Every original allowed input must meet relation.
    def open_on(bits):
        product=identity
        for j,s in enumerate(bits): product=mul(product,rows[j][s])
        return xor(encrypted,mask(product,sid))
    if false:
        # Just x either 0 or 1. Both results are false despite ciphertext leak.
        assert all(open_on((x,x,x,x))!=secret for x in (0,1))
        assert all(mul(mul(mul(g[0][x],g[1][x]),g[2][x]),g[3][x])==identity for x in (0,1))
        accepted_inputs=0
    else:
        assert open_on((1,1,1,1))==secret
        assert all(open_on((x,y,x,y))!=secret for x,y in [(0,0),(0,1),(1,0)])
        accepted_inputs=1
    return {'n':n,'false':false,'accepted_inputs':accepted_inputs,'public_branch_rows':8,
       'conjugacy_candidates':len(opts),'secret_from_public_algebra':secret in recovered,
       'all_prescribed_false_inputs_reject':false, 'direct_public_word_recovery':direct_public_word_recovery, 'did_not_query_accepting_witness':True}

if __name__=='__main__':
    results=[test(n,f,1757+n*11+f) for n in (5,17,67) for f in (False,True)]
    print(json.dumps({'scope':'synthetic, no original source/FE/Bitcoin/QPT security', 'fixtures':results},indent=2,sort_keys=True))
