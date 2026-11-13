#!/usr/bin/env python3
"""R246 finite SHA algebra only: NOT Bitcoin/Syscoin or NIZK verification."""
import hashlib, struct, json
H=lambda x: hashlib.sha256(x).digest()
H2=lambda x: H(H(x))
X=lambda a,b: bytes(x^y for x,y in zip(a,b))
prev=H(b'known BTC anchor'); base=H(b'baseline child'); ref=110
x=prev+base+struct.pack('<I',ref)
headers=[]
for n in range(5000):
    hdr=(struct.pack('<I',0x20000000)+prev+H(b'coinbase'+struct.pack('<I',n))
         +struct.pack('<III',1700000000,0x207fffff,n))
    if H2(hdr)[0]==0: headers.append(hdr)
    if len(headers)==2: break
assert len(headers)==2 and headers[0]!=headers[1]
assert all(len(h)==80 and h[4:36]==prev for h in headers)
def tag(h): return b'\x6a\x27sys'+H(b'child'+h)+struct.pack('<I',ref)
proofs=[H(b'FS-style transcript'+x+h+tag(h)) for h in headers]
pads=[H(b'R246 pad'+p) for p in proofs]
assert pads[0]!=pads[1]
sigma=bytes(range(32)); checker=H(b'public-check'+sigma)
c=X(sigma,pads[0])
assert X(c,pads[0])==sigma and X(c,pads[1])!=sigma
public_pad=H(b'public prefix'+x)
c_public=X(sigma,public_pad)
recovered=X(c_public,H(b'public prefix'+x))
assert recovered==sigma and H(b'public-check'+recovered)==checker
# The same raw public-pad attack works for any false source statement x_false.
x_false=x+b'FALSE-source-qualification'
c_false=X(sigma,H(b'public prefix'+x_false))
assert X(c_false,H(b'public prefix'+x_false))==sigma
secret=H(b'builder-only salt'); salted=H(b'salted pad'+x+secret)
assert all(secret not in h for h in headers)
assert X(X(sigma,salted),salted)==sigma
print(json.dumps({'run':'R246_MIN','valid_toy_headers':2,
  'first_two_nonces':[struct.unpack('<I',h[-4:])[0] for h in headers],
  'source_proof_pads_different':True,
  'public_prefix_recovers_without_witness':True,
  'false_statement_public_prefix_recovers':True,
  'secret_salt_absent_from_source':True,
  'status':'NONQUALIFYING source-like SHA tests, not consensus/NIZK/QPT'},sort_keys=True,indent=2))
