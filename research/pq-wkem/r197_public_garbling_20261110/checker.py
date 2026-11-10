#!/usr/bin/env python3
"""R197: hash-only public-garbling candidate, bounded counterexample, no security theorem."""
import hashlib, json, itertools
from collections import defaultdict

def H(tag, *parts):
    raw=tag.encode()+b'\0'+b''.join(len(x).to_bytes(4,'big')+x for x in parts)
    return hashlib.sha256(raw).digest()

def XOR(x,y): return bytes(a^b for a,b in zip(x,y))

def B(s): return s.to_bytes(4,'big')

def bits(label): return label[-1]&1

class Garble:
    def __init__(self,seed,fn):
        self.seed=seed
        self.wire={}
        self.tables={}
        self.gates=[]
        self.fn=fn
        self.add_wire('b')
        self.add_wire('not_b')
        self.add_wire('same_b')
        self.add_wire('accept')
        self.add_gate('not','b',None,'not_b',lambda a,b:1-a)
        self.add_gate('id','b',None,'same_b',lambda a,b:a)
        self.add_gate('and','not_b','same_b','accept',lambda a,b:a&b)
        self.K=H('key',seed)
        self.E=XOR(self.K,H('pad',self.wire['accept'][1]))
        self.CK=H('check',self.K)

    def add_wire(self,w):
        labs=[]
        for v in range(2):
            # random-looking labels with opposite permutation bits
            lab=bytearray(H('wire',self.seed,w.encode(),bytes([v])))
            lab[-1]=(lab[-1]&0xfe) | (v^(self.seed[0]&1))
            labs.append(bytes(lab))
        self.wire[w]=labs

    def add_gate(self,name,a,b,out,fn):
        table={}
        for vals in itertools.product((0,1),repeat=2 if b else 1):
            va=vals[0];vb=vals[1] if b else 0
            la=self.wire[a][va];lb=self.wire[b][vb] if b else b'none'
            row=(bits(la),bits(lb)) if b else (bits(la),)
            pad=H('garble-gate',name.encode(),la,lb)
            table[row]=XOR(pad,self.wire[out][fn(va,vb)])
        self.tables[name]=table
        self.gates.append((name,a,b,out))

    def evaluate(self,bval):
        cache={'b':self.wire['b'][bval]}
        for name,a,b,out in self.gates:
            la=cache[a];lb=cache[b] if b else b'none'
            row=(bits(la),bits(lb)) if b else (bits(la),)
            cache[out]=XOR(self.tables[name][row],H('garble-gate',name.encode(),la,lb))
        return cache['accept']

    def adversarial_saturate(self):
        # Adversary sees BOTH external input labels; closes local gate
        # evaluation under all locally available labels, unconstrained by
        # a single global assignment of the shared input b.
        sets={'b':set(self.wire['b'])}
        for name,a,b,out in self.gates:
            outs=set()
            for la in sets[a]:
                for lb in (sets[b] if b else [b'none']):
                    row=(bits(la),bits(lb)) if b else (bits(la),)
                    if row in self.tables[name]:
                        outs.add(XOR(self.tables[name][row],H('garble-gate',name.encode(),la,lb)))
            sets[out]=outs
        return sets

    def recover(self,output):
        k=XOR(self.E,H('pad',output))
        return k if H('check',k)==self.CK else None

def run():
    counts=defaultdict(int)
    for trial in range(120):
        seed=B(trial)
        g=Garble(seed,None)
        # Source checker R(b)=(NOT b) AND b is FALSE for every consistent b.
        for b in (0,1):
            out=g.evaluate(b)
            assert out==g.wire['accept'][0]
            assert g.recover(out) is None
            counts['all_honest_false_paths_reject']+=1
        closure=g.adversarial_saturate()
        # Contradictory local assignments yield both TRUE child labels.
        assert g.wire['not_b'][1] in closure['not_b']
        assert g.wire['same_b'][1] in closure['same_b']
        assert g.wire['accept'][1] in closure['accept']
        assert g.recover(g.wire['accept'][1]) == g.K
        counts['false_instance_attack_gets_exact_key']+=1
        # Ensure gating by an independently public check-key does not help.
        assert len(closure['accept'])==2
        counts['public_check_key_disambiguates_output']+=1
        # Potential repair: bind all rows to a public transcript salt t=H(w).
        # Future w changes t, but Build fixes its encrypted rows once.
        # A setup-fixed salt will not work for both later legal witnesses;
        # publishing rows keyed on caller-selected t cannot authenticate t.
        w0=bytes([0])+seed
        w1=bytes([1])+seed
        t0=H('witness-global',w0);t1=H('witness-global',w1)
        # One concrete globally salted single-gate candidate. Both distinct
        # b are valid for a constant-TRUE relation. Build fixes t0 but all
        # future valid witnesses must open one identical true output label.
        true_label=H('salted-accept',seed)
        salt_table={}
        for i in (0,1):
            li=g.wire['b'][i]
            salt_table[i]=XOR(true_label,H('salted-pad',t0,li))
        open0=XOR(salt_table[0],H('salted-pad',t0,g.wire['b'][0]))
        open1=XOR(salt_table[1],H('salted-pad',t1,g.wire['b'][1]))
        assert open0==true_label and open1!=true_label
        counts['future_transcript_tweak_breaks_all_witness_correctness']+=1
    return {'run':'R197-public-garbling','counts':dict(sorted(counts.items())),
      'checks':sum(counts.values()),
      'conclusion':'false ORIGINAL instance leaks through public labels; transcript salt repair not instantiated',
      'scope':'abstract 1-bit fanout circuit; no BTC/SYS consensus verifier; no quantum security claims',
      'sha256_source':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
