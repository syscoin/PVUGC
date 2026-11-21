#!/usr/bin/env python3
"""R337 synthetic source-salted Yao label-translator experiment; NO ORIGINAL source evidence."""
import hashlib
import hmac
import json

def sha(x): return hashlib.sha256(x).digest()
def xor(x,y):
    assert len(x)==len(y)
    return bytes(a^b for a,b in zip(x,y))

def label(wire, bit): return sha(b'R337/label/'+wire.encode()+bytes([bit])+b'/seed')
def mask(tag, *keys): return sha(b'R337/gate-pad/'+tag.encode()+b''.join(keys))
def tag(tagname, out, *keys): return sha(b'R337/tag/'+tagname.encode()+out+b''.join(keys))[:16]

def gate(name, ins, outs, fn):
    import itertools
    rows=[]
    for bs in itertools.product((0,1),repeat=len(ins)):
        keys=[label(w,b) for w,b in zip(ins,bs)]
        out=label(outs,fn(*bs)); m=mask(name,*keys)
        rows.append((xor(out,m),tag(name,out,*keys)))
    return list(reversed(rows))

def eval_gate(name, table, *keys):
    m=mask(name,*keys)
    for c,t in table:
        out=xor(c,m)
        if hmac.compare_digest(t,tag(name,out,*keys)):
            return out
    raise ValueError('No authentic gate row for these labels')

def source_t(w): return sha(b'R337/claim/C987/source-witness/'+w)
def ephemeral(t, bit): return sha(b'R337/ephemeral/input/'+t+bytes([bit]))
def translator(t,bit): return xor(label('x',bit),ephemeral(t,bit))

gates={
    'id':gate('id',['x'],'a', lambda x:x),
    'not':gate('not',['x'],'b', lambda x:1-x),
    'and':gate('and',['a','b'],'o',lambda a,b:a&b)
}
S=sha(b'R337/frozen-safe-cancel-synthetic-only')
CT=xor(S,sha(b'R337/cancel-pad/'+label('o',1)))
assert S != CT

# Honest evaluations of FALSE circuit x AND (NOT x) never reach output=1.
for b in (0,1):
    k=label('x',b)
    a=eval_gate('id',gates['id'],k)
    nb=eval_gate('not',gates['not'],k)
    out=eval_gate('and',gates['and'],a,nb)
    assert out==label('o',0)
    assert out!=label('o',1)

# Static salt t0: valid arbitrary future other t1 cannot translate any input.
t0=source_t(b'known-setup-W0');t1=source_t(b'fresh-future-W1')
for bit in (0,1):
    bad_key=xor(translator(t0,bit),ephemeral(t1,bit))
    assert bad_key!=label('x',bit)
    for name in ('id','not'):
        try: eval_gate(name,gates[name],bad_key)
        except ValueError: pass
        else: raise AssertionError('Static salt translator unexpectedly worked on future W')

# Dynamic public translator is available for arbitrary unqualified source bytes.
fake0=b'completely-unqualified-fake-source-0'
fake1=b'completely-unqualified-fake-source-1'
k0=xor(translator(source_t(fake0),0),ephemeral(source_t(fake0),0))
k1=xor(translator(source_t(fake1),1),ephemeral(source_t(fake1),1))
assert k0==label('x',0) and k1==label('x',1)
# Incompatible source/bit assignments can now be spliced inside public garbling.
a_true=eval_gate('id',gates['id'],k1)
b_true=eval_gate('not',gates['not'],k0)
assert a_true==label('a',1) and b_true==label('b',1)
true_output=eval_gate('and',gates['and'],a_true,b_true)
assert true_output==label('o',1)
recovered=xor(CT,sha(b'R337/cancel-pad/'+true_output))
assert recovered==S

print(json.dumps({
 'candidate':'source-salted input translation for a static hash-garbled verifier',
 'relation':'FALSE x AND (NOT x); synthetic unqualified W values',
 'normal_evaluation':'both x=0 and x=1 evaluate to false output label',
 'static_salt':'future different W cannot decrypt gate rows',
 'dynamic_salt':'public fake-W evaluations disclose both input labels',
 'mix':'ID(x=1), NOT(x=0), AND(1,1) opens true output label',
 'unauthorized_exact_S_recovery':recovered==S,
 'original_AuxPoW':False,'QPT_security_proven':False
},sort_keys=True,indent=2))
