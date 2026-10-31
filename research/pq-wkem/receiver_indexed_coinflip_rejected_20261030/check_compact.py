import hashlib, json, random
R=random.Random(2117)
q=7; d=6; kappa=8; t=24; assertions=0

def check(condition):
    global assertions
    assert condition
    assertions+=1

def G(seed):
    return int.from_bytes(hashlib.shake_256(b'WKEM-OH-TOY-G'+seed.to_bytes(2,'big')).digest(3),'big')

def bits(values):
    return [(v>>b)&1 for v in values for b in range(3)]

def commit(sigma,values):
    rs=[R.randrange(256) for _ in bits(values)]
    return [G(r)^(sigma[j] if b else 0) for j,(r,b) in enumerate(zip(rs,bits(values)))],rs

def valid(sigma,C,values,rs):
    return all(C[j]==(G(r)^(sigma[j] if b else 0))
               for j,(r,b) in enumerate(zip(rs,bits(values))))

for trial in range(80):
    # Session 0: honest receiver's independent real CRS and fixed shares.
    sigma0=[R.getrandbits(t) for _ in range(18)]
    m00=[R.randrange(q) for _ in range(d)]
    m10=[R.randrange(q) for _ in range(d)]
    C00,r00=commit(sigma0,m00)
    C10,r10=commit(sigma0,m10)
    # Session 1: corrupt receiver creates trapdoored fake CRS and commitment.
    trap=[(R.randrange(256),R.randrange(256)) for _ in range(18)]
    sigma1=[G(a)^G(b) for a,b in trap]
    C11=[G(a) for a,b in trap]
    m01=[R.randrange(q) for _ in range(d)]
    C01,r01=commit(sigma1,m01)
    # All commitments precede openings. In each session receiver opens last.
    check(valid(sigma0,C10,m10,r10))
    check(valid(sigma0,C00,m00,r00))
    check(valid(sigma1,C01,m01,r01))
    target=[0]*d if trial%2==0 else [1,2,3,4,5,6]
    m11=[(target[j]-m00[j]-m10[j]-m01[j])%q for j in range(d)]
    r11=[trap[j][b] for j,b in enumerate(bits(m11))]
    check(valid(sigma1,C11,m11,r11))
    check(all((m00[j]+m10[j]+m01[j]+m11[j])%q==target[j]
              for j in range(d)))
    for j,(a,b) in enumerate(trap):
        other=1-bits(m11)[j]
        check(C11[j]==(G(trap[j][other])^(sigma1[j] if other else 0)))
print(json.dumps({'result':'UNSAFE','cases':80,'assertions':assertions,
                  'attack':'corrupt later receiver fixes final shared SOURCE',
                  'scope':'toy algebra, no QPT claim'},sort_keys=True))
