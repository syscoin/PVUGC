"""Bounded toy: a public Merkle root ignores signer randomizer key. NOT FIPS 205."""
import hashlib, json, math

def H(*args):
    h=hashlib.sha256()
    for a in args: h.update(bytes([len(a)])); h.update(a)
    return h.digest()[:2]

def leaves(z,p):
    return [H(H(bytes([z]),p,bytes([i]))) for i in range(4)]

def root(z,p):
    l=leaves(z,p)
    return H(H(l[0],l[1]),H(l[2],l[3]))

def sign(z,p,rt,m,R):
    j=H(R,rt,m)[0]%4
    l=leaves(z,p)
    secret=H(bytes([z]),p,bytes([j]))
    return R,j,secret,l[j^1],H(l[2],l[3]) if j<2 else H(l[0],l[1])

def verify(p,rt,m,sig):
    R,j,secret,sibling,other=sig
    if j!=H(R,rt,m)[0]%4: return False
    leaf=H(secret)
    pair=H(leaf,sibling) if j%2==0 else H(sibling,leaf)
    calculated=H(pair,other) if j<2 else H(other,pair)
    return calculated==rt

checks=0
records=[]
for z,prf,p in [(7,13,b'aa'),(51,90,b'bb'),(201,177,b'cc')]:
    rt=root(z,p)
    found=[x for x in range(256) if root(x,p)==rt]
    assert z in found; checks+=1
    R=H(bytes([prf]),b'PRF',b'message')
    forged_R=b'zz'
    assert forged_R!=R;checks+=1
    assert verify(p,rt,b'message',sign(z,p,rt,b'message',R));checks+=1
    assert verify(p,rt,b'message',sign(found[0],p,rt,b'message',forged_R));checks+=1
    v=[1/math.sqrt(256)]*256
    marked=set(found)
    theta=math.asin(math.sqrt(len(marked)/256))
    t=round(math.pi/(4*theta)-0.5)
    for i in range(t+1):
        probability=sum(v[j]**2 for j in marked)
        assert abs(probability-math.sin((2*i+1)*theta)**2)<1e-9; checks+=1
        if i<t:
            v=[-a if j in marked else a for j,a in enumerate(v)]
            avg=sum(v)/256
            v=[2*avg-a for a in v]
    records.append({'matching_seeds':len(found),'grover_iterations':t,'final_success':round(probability,9)})
params=[{'n_bytes':n,'root_query_exponent':4*n,'signature_bytes':s} for n,s in [(16,7856),(24,16224),(32,29792)]]
assert [p['root_query_exponent'] for p in params]==[64,96,128];checks+=1
print(json.dumps({'run':689,'toy_only':True,'passed_checks':checks,'fixtures':records,'parameter_query_bounds':params},sort_keys=True,separators=(',',':')))
