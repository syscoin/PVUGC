"""Research-only Merkle transcript extractor; NOT a witness KEM or Bitcoin verifier."""
import hashlib,json
N=0

def test(ok):
 global N
 assert ok
 N+=1

def b(*a):return b''.join(len(t).to_bytes(2,'big')+t for t in a)
def h(domain,*a,width=32):return hashlib.sha256(b'MCPC/v2'+b(domain,*a)).digest()[:width]
def leaf(n,i,v,ctx,width=32):return h(b'L',ctx,n.to_bytes(2,'big'),i.to_bytes(2,'big'),bytes([v]),width=width)
def inner(a,c,width=32):return h(b'N',a,c,width=width)
def commit(bits,ctx,width=32):
 n=len(bits);p=1<<(n-1).bit_length();layer=[leaf(n,i,v,ctx,width) for i,v in enumerate(bits)]
 layer += [h(b'PAD',ctx,n.to_bytes(2,'big'),i.to_bytes(2,'big'),width=width) for i in range(n,p)]
 layers=[layer]
 while len(layer)>1:
  layer=[inner(layer[i],layer[i+1],width) for i in range(0,len(layer),2)];layers.append(layer)
 return layer[0],layers

def path(layers,i):
 p=[]
 for layer in layers[:-1]:p.append(layer[i^1]);i//=2
 return p

def verify(root,n,ctx,i,v,p,width=32):
 if not 0<=i<n or v not in (0,1) or len(p)!=(n-1).bit_length():return False
 z=leaf(n,i,v,ctx,width)
 for sibling in p:
  z=inner(z,sibling,width) if i%2==0 else inner(sibling,z,width);i//=2
 return z==root

def collision(root,n,ctx,i,v,p,u,q,width=32):
 if v==u or not verify(root,n,ctx,i,v,p,width) or not verify(root,n,ctx,i,u,q,width):return None
 x=leaf(n,i,v,ctx,width);y=leaf(n,i,u,ctx,width)
 if x==y:return (b'MCPC/v2'+b(b'L',ctx,n.to_bytes(2,'big'),i.to_bytes(2,'big'),bytes([v])),b'MCPC/v2'+b(b'L',ctx,n.to_bytes(2,'big'),i.to_bytes(2,'big'),bytes([u])))
 for a,z in zip(p,q):
  A=b'MCPC/v2'+(b(b'N',x,a) if i%2==0 else b(b'N',a,x))
  B=b'MCPC/v2'+(b(b'N',y,z) if i%2==0 else b(b'N',z,y))
  x=hashlib.sha256(A).digest()[:width];y=hashlib.sha256(B).digest()[:width]
  if x==y:
   assert A!=B
   return A,B
  i//=2
 raise AssertionError('Opposite openings without underlying collision')

def original(read):
 a=read(0);c=read(1)
 if a==c:return False
 d=read(2);e=read(3)
 if d!=e:return False
 z=read(4 if a else 5)
 return z==1 and read(0)==a

def false_original(read):return read(0)==0 and read(0)==1

def extract(root,n,ctx,trace,reader,width=32):
 pos=0;seen={}
 class Fail(Exception):pass
 class Hit(Exception):pass
 found=None
 def read(i):
  nonlocal pos,found
  if pos==len(trace):raise Fail
  j,v,p=trace[pos];pos+=1
  if i!=j or not verify(root,n,ctx,j,v,p,width):raise Fail
  if j in seen and seen[j][0]!=v:
   found=collision(root,n,ctx,j,seen[j][0],seen[j][1],v,p,width);raise Hit
  seen[j]=(v,p);return v
 try:accepted=reader(read)
 except Fail:return ('reject',None)
 except Hit:return ('collision',found)
 if not accepted or pos!=len(trace):return ('reject',None)
 w=[0]*n
 for j,(v,_) in seen.items():w[j]=v
 assert reader(lambda j:w[j])
 return ('witness',w)

def main():
 ctx=b'RELATION|CLAIM|UTXO|SLOT|ANCHOR|VK|PATH'
 for t in range(30):
  w=[(t>>i)&1 for i in range(6)];w[1]=1-w[0];w[3]=w[2];w[4 if w[0] else 5]=1
  root,layers=commit(w,ctx);trace=[]
  def read(i):trace.append((i,w[i],path(layers,i)));return w[i]
  test(original(read));status,recovered=extract(root,6,ctx,trace,original)
  test(status=='witness' and original(lambda i:recovered[i]))
  corrupted=list(trace);i,v,p=corrupted[-1];corrupted[-1]=(i,1-v,p)
  test(extract(root,6,ctx,corrupted,original)[0]=='reject')
  other=list(w);other[0]^=1;other[1]=1-other[0];rt,lt=commit(other,ctx)
  swapped=list(trace);swapped[0]=(0,other[0],path(lt,0))
  test(extract(root,6,ctx,swapped,original)[0]=='reject')
 for val in (0,1):
  rt,lt=commit([val,0],ctx)
  test(extract(rt,2,ctx,[(0,0,path(lt,0)),(0,1,path(lt,0))],false_original)[0]=='reject')
 # Actually create opposite accepted openings of 8-bit *weak* digest and extract a collision.
 wc=b'WEAK-COLLISION';n=2;first=leaf(n,0,0,wc,1);second=leaf(n,0,1,wc,1)
 lookup={inner(first,bytes([j]),1):bytes([j]) for j in range(256)}
 match=None
 for j in range(256):
  rt=inner(second,bytes([j]),1)
  if rt in lookup:match=(rt,lookup[rt],bytes([j]));break
 test(match is not None)
 rt,s0,s1=match
 status,pair=extract(rt,2,wc,[(0,0,[s0]),(0,1,[s1])],false_original,1)
 test(status=='collision' and pair[0]!=pair[1] and hashlib.sha256(pair[0]).digest()[:1]==hashlib.sha256(pair[1]).digest()[:1])
 print(json.dumps({'assert_checks':N,'adaptive_true_cases':30,'false_cases':2,'collision':'one-byte deliberately weak hash, NOT SHA-256 break','full_native_release':'NOT CONSTRUCTED'},sort_keys=True))

if __name__=='__main__':main()
