# R208 public-support key extraction. Synthetic Boolean constraint field, NOT original BTC/SYS WE.
import hashlib,json
q=257
F=[{(0,0):-1,(1,0):1,(0,1):1,(1,1):-2},
   {(2,0):1,(1,0):-1},{(0,2):1,(0,1):-1}]
checks=0

def rand(s,k):return int.from_bytes(hashlib.sha256((str(s)+':'+k).encode()).digest(),'big')
def add(v,t,c):
    n=(v.get(t,0)+c)%q
    if n:v[t]=n
    else:v.pop(t,None)
def term(f,m,c):
    out={}
    for x,a in f.items():add(out,(m[0]+x[0],m[1]+x[1]),a*c)
    return out
def reduce(v,B):
    v=dict(v)
    for t,row in sorted(B.items()):
        if t in v:
            c=v[t]
            for x,a in row.items():add(v,x,-c*a)
    return v
def basis(rows):
    B={}
    for row in rows:
        v=reduce(row,B)
        if v:
            t=min(v); z=pow(v[t],-1,q)
            B[t]={x:a*z%q for x,a in v.items()}
    return B
def extract(P):
    # Crucially: no setup seed, mask supports, trace, or witness argument.
    C={(t[0]-u[0],t[1]-u[1]) for t in P for f in F for u in f
       if t[0]>=u[0] and t[1]>=u[1]}
    B=basis([term(f,m,1) for m in sorted(C) for f in F])
    E=reduce({(0,0):1},B); V=reduce(P,B)
    assert E
    t=min(E); K=V.get(t,0)*pow(E[t],-1,q)%q
    assert all(V.get(x,0)==K*a%q for x,a in E.items())
    return K,C

def main():
    global checks
    for s in range(12):
        K=1+rand(s,'key')%256
        private=[];P={(0,0):K}
        for j,f in enumerate(F):
            masks=[((0,0),1+rand(s,'constant')%256)] if j==0 else []
            for k in range(2):
                m=(3+rand(s,f'x{j}{k}')%30,3+rand(s,f'y{j}{k}')%30)
                masks.append((m,1+rand(s,f'coef{j}{k}')%256))
            private.extend(m for m,c in masks)
            for m,c in masks:
                for t,a in term(f,m,c).items():add(P,t,a)
        got,C=extract(P)
        assert got==K; checks+=1
        assert P.get((0,0),0)!=K; checks+=1
        assert set(private)<=C;checks+=1
        for a,b in [(0,1),(1,0)]:
            assert all(sum(co*pow(a,t[0])*pow(b,t[1]) for t,co in f.items())%q==0 for f in F)
            assert sum(co*pow(a,t[0])*pow(b,t[1]) for t,co in P.items())%q==K
            checks+=2
    return {'run':'R208-repro','seeds':12,'assertions':checks,
      'result':'full-public secret-support recovery succeeds, no original source release'}
if __name__=='__main__':print(json.dumps(main(),sort_keys=True))
