#!/usr/bin/env python3
"""R280: exact SHA256d 80-byte synthetic PoW Boolean circuit and SHA-garbled release.
All source histories/AuxPoW are synthetic. This is a deliberately insecure candidate.
"""
import hashlib, json, random, sys

# Public synthetic claim/capsule domain binding; this is not real x_W serialization.
CONTEXT=hashlib.sha256(b"R280|BTC-SYS|claim-UTXO|withdrawal-burn-amount-recipient|baseline|source-window|LC-depth|deadline-reset|safe-cancel-message|VK|capsule-id").digest()
from collections import Counter

class Circuit:
    def __init__(self):
        self.nodes=[] # (op, x, y), id = position + 2; constant 0 / 1 are 0/1
        self.inputs=[]
    def inp(self):
        a=self._gate('IN', -1, -1)
        self.inputs.append(a)
        return a
    def _gate(self, op, x, y):
        t=2+len(self.nodes); self.nodes.append((op,x,y)); return t
    def NOT(self,a):
        if a <2: return 1-a
        return self._gate('NOT',a,-1)
    def XOR(self,a,b):
        if a==b: return 0
        if a==0:return b
        if b==0:return a
        if a==1:return self.NOT(b)
        if b==1:return self.NOT(a)
        return self._gate('XOR',a,b)
    def AND(self,a,b):
        if a==0 or b==0:return 0
        if a==1:return b
        if b==1:return a
        if a==b:return a
        return self._gate('AND',a,b)
    def OR(self,a,b):
        if a==1 or b==1:return 1
        if a==0:return b
        if b==0:return a
        if a==b:return a
        return self._gate('OR',a,b)
    def ADD(self,x,y): # 32 bits big endian arrays, ripple carry from right
        out=[None]*32; carry=0
        for i in range(31,-1,-1):
            t=self.XOR(x[i],y[i]);out[i]=self.XOR(t,carry)
            carry=self.OR(self.AND(x[i],y[i]),self.AND(t,carry))
        return out
    def sum(self,*xs):
        acc=xs[0]
        for x in xs[1:]:acc=self.ADD(acc,x)
        return acc
    def const_word(self,u):return [(u>>i)&1 for i in range(31,-1,-1)]
    def ROR(self,x,n):return x[-n:]+x[:-n]
    def SHR(self,x,n):return [0]*n+x[:-n]
    def W_XOR(self,*xs):
        ans=xs[0]
        for x in xs[1:]:ans=[self.XOR(a,b) for a,b in zip(ans,x)]
        return ans
    def w_ch(self,x,y,z):
        return [self.XOR(self.AND(a,b),self.AND(self.NOT(a),c)) for a,b,c in zip(x,y,z)]
    def w_maj(self,x,y,z):
        return [self.XOR(self.XOR(self.AND(a,b),self.AND(a,c)),self.AND(b,c)) for a,b,c in zip(x,y,z)]
    K=(0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
       0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
       0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
       0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
       0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
       0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
       0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
       0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
    IV=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
    def compress(self,state,chunk):
        w=[chunk[i*32:(i+1)*32] for i in range(16)]
        for i in range(16,64):
            a=w[i-15];b=w[i-2]
            s0=self.W_XOR(self.ROR(a,7),self.ROR(a,18),self.SHR(a,3))
            s1=self.W_XOR(self.ROR(b,17),self.ROR(b,19),self.SHR(b,10))
            w.append(self.sum(w[i-16],s0,w[i-7],s1))
        a,b,c,d,e,f,g,h=state
        for i in range(64):
            S1=self.W_XOR(self.ROR(e,6),self.ROR(e,11),self.ROR(e,25))
            T1=self.sum(h,S1,self.w_ch(e,f,g),self.const_word(self.K[i]),w[i])
            S0=self.W_XOR(self.ROR(a,2),self.ROR(a,13),self.ROR(a,22))
            T2=self.sum(S0,self.w_maj(a,b,c))
            a,b,c,d,e,f,g,h=self.ADD(T1,T2),a,b,c,self.ADD(d,T1),e,f,g
        return [self.ADD(z,y) for z,y in zip(state,(a,b,c,d,e,f,g,h))]
    def sha256(self,bits):
        assert len(bits)%8==0
        bitlen=len(bits)
        bits=bits+[1]
        bits.extend([0]*((448-len(bits)%512)%512))
        bits.extend([(bitlen>>i)&1 for i in range(63,-1,-1)])
        state=[self.const_word(v) for v in self.IV]
        for j in range(0,len(bits),512):state=self.compress(state,bits[j:j+512])
        return [b for w in state for b in w]
    def compute(self, inputbits, outputs):
        assert len(inputbits)==len(self.inputs)
        vals=[0,1]
        ii=iter(inputbits)
        for op,x,y in self.nodes:
            if op=='IN':z=next(ii)
            elif op=='NOT':z=1-vals[x]
            elif op=='AND':z=vals[x]&vals[y]
            elif op=='OR':z=vals[x]|vals[y]
            elif op=='XOR':z=vals[x]^vals[y]
            else:raise AssertionError(op)
            vals.append(z)
        return [vals[v] for v in outputs],vals


def bit_bytes(bb):return bytes(int(''.join(map(str,bb[i:i+8])),2) for i in range(0,len(bb),8))
def bits_bytes(bb):return [(x>>i)&1 for x in bb for i in range(7,-1,-1)]
def sha256d(b):return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def make_header(nonce):
    prefix=hashlib.sha256(b'R280 domain claim-prefix synthetic parent header').digest()+hashlib.sha256(b'source root synthetic').digest()+bytes.fromhex('fa010000')+bytes.fromhex('ffff001d')
    assert len(prefix)==72
    # fixed nTime to reach first 76
    return prefix+bytes.fromhex('00000067')+nonce.to_bytes(4,'little')
def op_apply(op,a,b):
    return ((a^b) if op=='XOR' else (a&b) if op=='AND' else (a|b) if op=='OR' else (1-a) if op=='NOT' else None)

# Point-and-permute style 128-bit labels. Public input label pairs and garbled gate rows.
def hpad(idx,L,R):return hashlib.sha256(b'R280-GARBLE'+CONTEXT+idx.to_bytes(4,'big')+L+(R or b'')).digest()[:16]
def xor16(x,y):return bytes(a^b for a,b in zip(x,y))

def garble(circuit, rng):
    lab=[(b'\0'*15+b'\0',b'\0'*15+b'\1'),(b'\0'*15+b'\1',b'\0'*15+b'\0')]
    tabs=[]
    for idx,(op,x,y) in enumerate(circuit.nodes,2):
        l0=bytearray(rng.randbytes(16));l1=bytearray(rng.randbytes(16))
        pbit=rng.randrange(2)  # randomized point-and-permute bit, not a semantic-bit leak
        l0[-1]=(l0[-1]&254)|pbit;l1[-1]=(l1[-1]&254)|(pbit^1)
        lab.append((bytes(l0),bytes(l1)))
        if op=='IN':tabs.append([]);continue
        table=[None]*(2 if op=='NOT' else 4)
        for a in (0,1):
            for b in ((0,) if op=='NOT' else (0,1)):
                la=lab[x][a];lb=(b'' if op=='NOT' else lab[y][b]);t=(la[-1]&1) if op=='NOT' else (la[-1]&1)*2+(lb[-1]&1)
                table[t]=xor16(lab[idx][op_apply(op,a,b)],hpad(idx,la,lb))
        assert all(v is not None for v in table)
        tabs.append(table)
    return lab,tabs

def evalgarble(c,labels,tables,bits,output):
    active={0:labels[0][0],1:labels[1][1]}
    idx_in=0
    for idx,(op,x,y) in enumerate(c.nodes,2):
        if op=='IN': active[idx]=labels[idx][bits[idx_in]];idx_in+=1;continue
        la=active[x];lb=(b'' if op=='NOT' else active[y])
        row=(la[-1]&1) if op=='NOT' else 2*(la[-1]&1)+(lb[-1]&1)
        active[idx]=xor16(tables[idx-2][row],hpad(idx,la,lb))
    return active[output]

def closure(c,labels,tables,output):
    # Source-free public-closure adversary: all witness-input labels public.
    pairs=[labels[0],labels[1]]
    for idx,(op,x,y) in enumerate(c.nodes,2):
        if op=='IN':pairs.append(labels[idx]);continue
        out=[None,None]
        for a in (0,1):
            for b in ((0,) if op=='NOT' else (0,1)):
                la=pairs[x][a];lb=(b'' if op=='NOT' else pairs[y][b])
                row=(la[-1]&1) if op=='NOT' else 2*(la[-1]&1)+(lb[-1]&1)
                dec=xor16(tables[idx-2][row],hpad(idx,la,lb))
                z=op_apply(op,a,b)
                if out[z] is None:out[z]=dec
                else:assert out[z]==dec
        # for NOT, AND, OR, XOR all labels available by one local truth assignment.
        assert None not in out
        pairs.append(tuple(out))
    return pairs[output][1]

def main():
    rng=random.Random(28020261114)
    # Build literal actual SHA256d on 80-byte synthetic parent header, four nonce bytes variable.
    c=Circuit();bb=[];hb=make_header(0)
    for k in range(80):
        for j in range(8):
            bb.append(c.inp() if k>=76 else (hb[k]>>(7-j))&1)
    digest=c.sha256(c.sha256(bb))
    # variable claim-context validity flag. FALSE instance intentionally unsatisfiable
    # because claim flag is immutable zero; nonce can still have PoW.
    assert len(c.inputs)==32 and len(digest)==256
    # adversary gets both labels for every nonce bit, BEFORE it sees source proof
    powgate=1
    for i in range(8):powgate=c.AND(powgate,c.NOT(digest[i]))
    outt=powgate
    # For FALSE, add a contradictory subcircuit rather than an explicit constant-zero output.
    # Keep FALSE bit as real syntactic condition x AND NOT x; no constant simplification across signals
    fresh=c.inp() # separate unknown source-context flag, private witness but fixed FALSE via public forced values
    # final formula Pow AND (fresh AND NOT fresh) is unsatisfiable regardless of extra input
    contradictory=c.AND(fresh,c.NOT(fresh));outf=c.AND(powgate,contradictory)
    assert outf >= 2
    powgood=None
    for nonce in range(10000):
        h=sha256d(make_header(nonce))
        if h[0]==0:powgood=nonce;break
    assert powgood is not None
    def nin(n):return bits_bytes(n.to_bytes(4,'little'))
    good=nin(powgood)+[0]
    got, _=c.compute(good,digest)
    assert bit_bytes(got)==sha256d(make_header(powgood))
    assert c.compute(good,[powgate])[0]==[1]
    assert c.compute(good,[outf])[0]==[0]
    # Independent hashlib comparisons for the full 256-bit digest, not merely target bits.
    fixture_nonces=[0,1,2,3,4,5,7,9,15,31,63,127,255,511,1023,4095]
    for n in fixture_nonces:
        computed,_=c.compute(nin(n)+[n&1],digest)
        assert bit_bytes(computed)==sha256d(make_header(n))
        assert c.compute(nin(n)+[n&1],[outf])[0]==[0]
    labels,tables=garble(c,rng)
    secret=rng.randbytes(32)
    VK=hashlib.sha256(b'R280-SYNTHETIC-VK'+CONTEXT+secret).hexdigest()
    # Build publishes only input label pairs, constants, tables, E, VK, NOT internal labels.
    pub_labels={0:labels[0],1:labels[1],**{idx:labels[idx] for idx in c.inputs}}
    assert outt not in pub_labels and outf not in pub_labels
    pad=lambda L: hashlib.sha256(b'R280-SIG'+CONTEXT+L).digest()
    E=bytes(a^b for a,b in zip(secret,pad(labels[outt][1])))
    def open_key(label):return bytes(a^b for a,b in zip(E,pad(label)))
    l=evalgarble(c,pub_labels,tables,good,outt)
    correct=(l==labels[outt][1] and open_key(l)==secret)
    # Two real SHA256d synthetic header puzzles, both satisfying the same fixed predicate.
    other=next(n for n in range(powgood+1,20000) if sha256d(make_header(n))[0]==0)
    other_bits=nin(other)+[1]
    other_gate=c.compute(other_bits,[outt])[0]==[1]
    other_open=open_key(evalgarble(c,pub_labels,tables,other_bits,outt))==secret
    assert other_gate and other_open
    # In a FALSE synthetic source instance, output is Pow AND (f AND NOT f).
    EF=bytes(a^b for a,b in zip(secret,pad(labels[outf][1])))
    forged_label=closure(c,pub_labels,tables,outf)
    stolen=bytes(a^b for a,b in zip(EF,pad(forged_label)))
    assert forged_label==labels[outf][1] and stolen==secret
    assert hashlib.sha256(b'R280-SYNTHETIC-VK'+CONTEXT+stolen).hexdigest()==VK
    # TRUE also leaks without witness
    stolen_true=open_key(closure(c,pub_labels,tables,outt));assert stolen_true==secret
    result=dict(status='NONQUALIFYING',source='synthetic-header; true SHA256d 80-byte circuit; no full AuxPoW',
                circuit_gates=len(c.nodes),input_bits=len(c.inputs),garbled_rows=sum(map(len,tables)),
                pow_nonce=powgood, second_pow_nonce=other,sha256d=sha256d(make_header(powgood)).hex(),
                complete_true_open=correct,second_valid_open=other_open,
                unsatisfiable_false_output=(c.compute(good,[outf])[0]==[0] and c.compute(other_bits,[outf])[0]==[0]),
                public_false_recovery=stolen==secret,public_true_recovery=stolen_true==secret,
                public_label_pairs=len(pub_labels),context_hash=CONTEXT.hex(),vk_sha256=VK,sha256d_regression_cases=len(fixture_nonces)+2,
                tests='actual SHA256d digest matches circuit; all-wire public-closure without a qualifying certificate')
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
