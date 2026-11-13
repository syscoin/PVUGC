#!/usr/bin/env python3
"""R205 second experiment: full-public label saturation on unsatisfiable SHA-garbled Boolean circuit.
Honest inputs x satisfy x AND (NOT x) = 0; attacker holding both input labels
recovers the protected output-1 label by mixing incompatible local wire states.
This is a deterministic functional break, NOT a QPT/Bitcoin implementation.
"""
import hashlib,json

def H(t,*parts):
    msg=t.encode()+b'\0'+b''.join(len(a).to_bytes(4,'big')+a for a in parts)
    return hashlib.sha256(msg).digest()

def X(a,b):return bytes(x^y for x,y in zip(a,b))

def lab(seed,w,b):
    out=bytearray(H('R205-label',seed,w.encode(),bytes([b])))
    out[-1]=(out[-1]&254)|b
    return bytes(out)

def build(seed):
    Xl=[lab(seed,'x',i) for i in range(2)]
    Nl=[lab(seed,'not_x',i) for i in range(2)]
    Zl=[lab(seed,'x_and_not_x',i) for i in range(2)]
    nr=[None]*2; ar=[None]*4
    for b in range(2):
        nr[Xl[b][-1]&1]=X(Nl[1-b],H('not-gate',seed,Xl[b]))
    for b in range(2):
        for c in range(2):
            ar[2*(Xl[b][-1]&1)+(Nl[c][-1]&1)]=X(Zl[b&c],H('and-gate',seed,Xl[b],Nl[c]))
    sigma=H('frozen-cancel-sig',seed)
    pub={'not_rows':nr,'and_rows':ar,'seed':seed,
         'pad':X(sigma,H('pad',seed,Zl[1])), 'check':H('check',seed,sigma)}
    # SOURCE INPUT LABELS PUBLIC: needed for any input bit to compute gate
    pub['input_labels']=Xl[:]
    return pub,(Xl,Nl,Zl),sigma

def NOT(p,x):return X(p['not_rows'][x[-1]&1],H('not-gate',p['seed'],x))

def AND(p,x,y):return X(p['and_rows'][2*(x[-1]&1)+(y[-1]&1)],H('and-gate',p['seed'],x,y))

def DECRYPT(p,z):
    s=X(p['pad'],H('pad',p['seed'],z))
    return s if H('check',p['seed'],s)==p['check'] else None

def main():
    count={'honest_inputs_always_false':0,'unreachable_true_label_recovered':0,
           'fabricated_witness_does_not_exist':0,'all_local_gate_tables_saturate':0}
    for n in range(128):
        p, labels, sigma=build(n.to_bytes(4,'big'))
        xl,nl,zl=labels
        for b in range(2):
            # All honest Boolean inputs evaluate false.
            z=AND(p,xl[b],NOT(p,xl[b]))
            assert z==zl[0] and DECRYPT(p,z) is None
            count['honest_inputs_always_false']+=1
        # SAT(x AND NOT x) is FALSE by Boolean algebra, no source witness exists.
        assert not any(b and (1-b) for b in range(2))
        count['fabricated_witness_does_not_exist']+=1
        # Full-public attacker computes both not_x labels, discards global occurrence consistency.
        recovered_n=[NOT(p,xl[b]) for b in range(2)]
        assert recovered_n[0]==nl[1] and recovered_n[1]==nl[0]
        z=AND(p,xl[1],recovered_n[0]) # uses x=1 from one local trace and not_x=1 from another
        assert z==zl[1] and DECRYPT(p,z)==sigma
        count['unreachable_true_label_recovered']+=1
        # Gate-by-gate saturation: four independent AND-input combinations, output BOTH labels.
        reachable={AND(p,a,b) for a in p['input_labels'] for b in recovered_n}
        assert reachable=={zl[0],zl[1]}
        count['all_local_gate_tables_saturate']+=1
    result={'run':'R205-GARBLED-UNSAT-SATURATION','functional_assertions':sum(count.values()),
            'counts':count,'classification':'unconditional full-public key release on unsatisfiable source Boolean relation',
            'scope':'Toy hash-garbled gates; not actual SHA circuit or Syscoin evidence',
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
