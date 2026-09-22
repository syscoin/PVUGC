import random, json, math
from collections import Counter

PI = {0:1,1:0,2:3,3:4,4:2}
ORBITS = [[0,1],[2,3,4]]

def inv_mod(a,q):
    return pow(a%q,-1,q)

def egcd(a,b):
    if b==0: return (a,1,0)
    g,x,y=egcd(b,a%b)
    return g,y,x-(a//b)*y

def matmul(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]

def eye(n):
    return [[1 if i==j else 0 for j in range(n)] for i in range(n)]

def matinv(A,q):
    n=len(A)
    M=[[(A[i][j]%q) for j in range(n)] + eye(n)[i] for i in range(n)]
    r=0
    for c in range(n):
        p=next(i for i in range(r,n) if M[i][c]%q)
        M[r],M[p]=M[p],M[r]
        z=inv_mod(M[r][c],q)
        M[r]=[(z*x)%q for x in M[r]]
        for i in range(n):
            if i!=r and M[i][c]%q:
                z=M[i][c]%q
                M[i]=[(M[i][j]-z*M[r][j])%q for j in range(2*n)]
        r+=1
    return [row[n:] for row in M]

def det2(A,q):
    return (A[0][0]*A[1][1]-A[0][1]*A[1][0])%q

def rand_gl2(rng,q):
    while True:
        A=[[rng.randrange(q) for _ in range(2)] for _ in range(2)]
        if det2(A,q)!=0: return A

def add_tokens_trial(rng,mod,n=7):
    # tau_i=id except final pi
    pads=[ [rng.randrange(mod) for _ in range(5)] for _ in range(n) ]
    # layer n aliases layer 0
    ks=[rng.randrange(mod) for _ in range(n)]
    K=sum(ks)%mod
    tok=[]
    for i in range(n):
        arr=[]
        for s in range(5):
            t = PI[s] if i==n-1 else s
            rnext = pads[0][t] if i==n-1 else pads[i+1][t]
            arr.append((ks[i]+pads[i][s]-rnext)%mod)
        tok.append(arr)
    def lap(start):
        s=start; val=0
        for i in range(n):
            val=(val+tok[i][s])%mod
            if i==n-1: s=PI[s]
        return val,s
    sums=[]
    for O in ORBITS:
        total=0
        for s in O:
            v,end=lap(s)
            assert end==PI[s]
            total=(total+v)%mod
        sums.append(total)
    assert sums[0]==(2*K)%mod
    assert sums[1]==(3*K)%mod
    rec=(sums[1]-sums[0])%mod
    assert rec==K
    return K,sums,rec

def mul_tokens_trial(rng,q,n=7):
    # group F_q^*
    pads=[[rng.randrange(1,q) for _ in range(5)] for _ in range(n)]
    ks=[rng.randrange(1,q) for _ in range(n)]
    K=1
    for k in ks: K=K*k%q
    tok=[]
    for i in range(n):
        arr=[]
        for s in range(5):
            t=PI[s] if i==n-1 else s
            rnext=pads[0][t] if i==n-1 else pads[i+1][t]
            arr.append(ks[i]*pads[i][s]*inv_mod(rnext,q)%q)
        tok.append(arr)
    def lap(start):
        s=start; val=1
        for i in range(n):
            val=val*tok[i][s]%q
            if i==n-1: s=PI[s]
        return val,s
    vals=[]
    for O in ORBITS:
        total=1
        for s in O:
            v,end=lap(s)
            total=total*v%q
        vals.append(total)
    assert vals[0]==pow(K,2,q)
    assert vals[1]==pow(K,3,q)
    rec=vals[1]*inv_mod(vals[0],q)%q
    assert rec==K
    return K,vals,rec

def eigvals_2x2(A,q):
    # brute roots of charpoly for tiny validation fields
    tr=(A[0][0]+A[1][1])%q
    det=det2(A,q)
    vals=[]
    for x in range(q):
        if (x*x-tr*x+det)%q==0:
            vals.append(x)
    # distinct semisimple fixture must have exactly two roots
    assert len(vals)==2 and vals[0]!=vals[1], (A,tr,det,vals)
    return sorted(vals)

def matrix_trial(rng,q=101,n=5):
    # choose eigenvalues nonzero, distinct, distinct sixth powers
    while True:
        l1,l2=rng.sample(range(1,q),2)
        if pow(l1,6,q)!=pow(l2,6,q):
            break
    K=[[l1,0],[0,l2]]
    I=eye(2)
    # choose factors K0=K, others I
    factors=[K]+[I for _ in range(n-1)]
    # frames per layer,state
    frames=[[rand_gl2(rng,q) for _ in range(5)] for _ in range(n)]
    tok=[]
    for i in range(n):
        arr=[]
        for s in range(5):
            t=PI[s] if i==n-1 else s
            R=frames[i][s]
            Rnext=frames[0][t] if i==n-1 else frames[i+1][t]
            C=matmul(matmul(matinv(R,q),factors[i],q),Rnext,q)
            arr.append(C)
        tok.append(arr)
    def lap(start):
        s=start; V=eye(2)
        for i in range(n):
            V=matmul(V,tok[i][s],q)
            if i==n-1: s=PI[s]
        return V,s
    powers=[]
    for O in ORBITS:
        V=eye(2)
        # multiply laps in orbit order so conjugating frames telescope
        s=O[0]
        for _ in range(len(O)):
            L,end=lap(s)
            V=matmul(V,L,q)
            s=end
        assert s==O[0]
        h=len(O)
        R=frames[0][O[0]]
        Kh=eye(2)
        for _ in range(h):
            Kh=matmul(Kh,K,q)
        expected=matmul(matmul(matinv(R,q),Kh,q),R,q)
        assert V==expected
        powers.append(V)
    A=eigvals_2x2(powers[0],q)
    B=eigvals_2x2(powers[1],q)
    # unique matching a^3=b^2
    pairs=[]
    for a in A:
        matches=[b for b in B if pow(a,3,q)==pow(b,2,q)]
        assert len(matches)==1,(l1,l2,A,B,a,matches)
        b=matches[0]
        pairs.append(b*inv_mod(a,q)%q)
    rec=sorted(pairs)
    truth=sorted([l1,l2])
    assert rec==truth,(truth,A,B,rec)
    return {"truth":truth,"eig_K2":A,"eig_K3":B,"recovered":rec}

def main():
    assert [s for s in range(5) if PI[s]==s]==[]
    assert sorted(len(o) for o in ORBITS)==[2,3]
    rng=random.Random(202609212016)
    add_counts={}
    for mod in [2,4,6,8,12,15,101]:
        for _ in range(100):
            add_tokens_trial(rng,mod)
        add_counts[str(mod)]=100
    mul_counts={}
    for q in [17,29,101]:
        for _ in range(100):
            mul_tokens_trial(rng,q)
        mul_counts[str(q)]=100
    examples=[]
    for _ in range(120):
        examples.append(matrix_trial(rng))
    out={
      "status":"PASS",
      "monodromy":{"fixed_points":[],"orbit_lengths":[2,3]},
      "additive_trials":add_counts,
      "multiplicative_trials":mul_counts,
      "matrix_trials":120,
      "matrix_example":examples[0],
      "claims_checked":[
        "orbit sums equal h*K in additive telescoping transfer",
        "2+3 orbit Bezout combination recovers K over every tested modulus",
        "orbit products equal K^h in multiplicative telescoping transfer",
        "K^3/K^2 recovers K without discrete logarithms",
        "nonabelian orbit products are conjugates of K^2 and K^3",
        "distinct-sixth-power semisimple matrix eigenvalues recover canonical K class"
      ]
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
