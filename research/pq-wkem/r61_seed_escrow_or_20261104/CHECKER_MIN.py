# R61 published executable finite checker: illustrative sizes, NOT PQ secure.
import hashlib,json,random
rng=random.Random(61); N=0
def ck(b):
 global N
 assert b;N+=1
def bits(v,k):return tuple((v>>i)&1 for i in range(k-1,-1,-1))
def num(a):return int(''.join(map(str,a)),2)
def xor(a,b):return tuple(i^j for i,j in zip(a,b))
def gen(r,A):
 s=num(r[:4]);e=[v-1 for v in r[4:]]
 return tuple(b for i,a in enumerate(A) for b in bits((a*s+e[i])%16,4))
def tree(k,A):
 layer=[k]
 for _ in range(2):
  layer=[child for r in layer for child in (gen(r,A)[:8],gen(r,A)[8:])]
 return tuple(b for r in layer for b in r)
def proj(allowed,v):
 # Boolean point-indicator masking, for two genuine ORIGINAL witness bits.
 out=[]
 for w in allowed:
  out.append(sum(x for i,x in enumerate(v) if i&~w==0)%257)
 return tuple(out)
def source(allowed,mu,eta):
 return proj(allowed,[128*mu+eta[0],*eta[1:]])
def openbit(z,idx):
 v=z[idx];d0=min(v,257-v);d1=min((v-128)%257,(128-v)%257)
 ck(min(d0,d1)<=4 and d0!=d1)
 return int(d1<d0)
def noise(i):return tuple((i*7+j*3)%3-1 for j in range(4))
def secret(s,e,t):return bits(s[0],4)+bits(s[1],4)+bits(e[0]+2,2)+bits(e[1]+2,2)+bits(t,4)
def sourceview(allowed,sec,j):return tuple(source(allowed,b,noise(j*17+i)) for i,b in enumerate(sec))
def y(A,s,e):return tuple((sum(a*x for a,x in zip(row,s))+e[i])%16 for i,row in enumerate(A))
def base(ctx,A0,A,G,ds,z,related):return repr((ctx,A0,A,G,ds,z,related))
def attach(ctx,A0,A,G,ds,z,tags,related):
 B=base(ctx,A0,A,G,ds,z,related)
 return (ctx,A0,A,G,ds,z,tuple((hashlib.sha3_256((str(t)+'CK'+B+str(j)).encode()).hexdigest(),hashlib.sha3_256((str(t)+'AUX'+B+str(j)).encode()).hexdigest()) for j,t in enumerate(tags)),related)
true0=(1,3);true1=(2,3);false=()
for trial in range(128):
 A0=tuple(rng.randrange(16) for _ in range(4));A=tuple(tuple(rng.randrange(16) for _ in range(2)) for _ in range(2))
 K=bits(rng.randrange(256),8);sig=bits(rng.randrange(1<<32),32);G=xor(sig,tree(K,A0))
 ds=[];zs=[];tags=[];secs=[]
 for j,allowed in enumerate((true0,true1)):
  s=(rng.randrange(16),rng.randrange(16));e=(rng.randrange(-2,2),rng.randrange(-2,2));t=rng.randrange(16)
  sec=secret(s,e,t);z=sourceview(allowed,sec,j);dj=xor(K,tuple(b for v in y(A,s,e) for b in bits(v,4)))
  for idx,w in enumerate(allowed):
   recovered=tuple(openbit(zi,idx) for zi in z)
   ck(recovered==sec)
   ss=(num(recovered[:4]),num(recovered[4:8]));ee=(num(recovered[8:10])-2,num(recovered[10:12])-2)
   recoveredK=xor(dj,tuple(b for v in y(A,ss,ee) for b in bits(v,4)))
   ck(recoveredK==K and xor(G,tree(recoveredK,A0))==sig)
  ds.append(dj);zs.append(z);tags.append(t);secs.append(sec)
 view=attach(('OR',trial),A0,A,G,tuple(ds),tuple(zs),tuple(tags),None)
 ck(len(view[6])==2)
 # Certified FALSE: source capsules independent of secret for identical source noise.
 fz=[]
 for j,sec in enumerate(secs):
  z=sourceview(false,sec,j); zprime=sourceview(false,tuple(1-b for b in sec),j)
  ck(z==zprime);fz.append(z)
 fv=attach(('FALSE',trial),A0,A,G,tuple(ds),tuple(fz),tuple(tags),('independent-related-opening',trial))
 sim=attach(('FALSE',trial),A0,A,G,tuple(ds),tuple(sourceview(false,secs[j],j) for j in range(2)),tuple(tags),('independent-related-opening',trial))
 ck(fv==sim)
 # The LWE-challenge simulator needs only Y and K, never target s/e to construct Z.
 U=bits(rng.randrange(256),8);changed=attach(('FALSE',trial),A0,A,G,(xor(K,U),ds[1]),tuple(fz),tuple(tags),('independent-related-opening',trial))
 ck(changed[5]==fv[5] and changed[4][0]==xor(K,U))
 # PRG challenge replacement flows through public Csig and correlated CK.
 p=gen(K,A0);other=bits(rng.randrange(65536),16)
 real=xor(sig,tuple(b for r in (p[:8],p[8:]) for b in gen(r,A0)))
 alt=xor(sig,tuple(b for r in (other[:8],other[8:]) for b in gen(r,A0)))
 ck(real==G)
 ck(attach(('H',trial),A0,A,alt,tuple(ds),tuple(fz),tuple(tags),None)[3]==alt)
old=4096*256*2+8*8192;new=1024*256*2+512*256*2+8192+8*1024
ck((old,new,old-new)==(2162688,802816,1359872))
print(json.dumps({'run':'R61-SEED-ESCROW-OR-20261104','assertions':N,'original_witness_openings':512,'false_full_view_couplings':128,'old_bytes':old,'new_bytes':new,'QPT':'NOT_TESTED','hard_TRUE':'UNPROVED'},sort_keys=True))
