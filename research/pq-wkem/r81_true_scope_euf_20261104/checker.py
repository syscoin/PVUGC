#!/usr/bin/env python3
"""R81: exact native signing-oracle substitution for true ORIGINAL sources.
Ed25519 and SHAKE are TEST FIXTURES, not a claim of PQ security.
The formal theorem uses an independently QPT-EUF-CMA native scheme."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import hashlib, json, itertools, random
RUN="R81-TRUE-SCOPE-EUF-20261104"
assertions=0
counters={"full_public_couplings":0,"original_witness_openings":0,
          "same_capability_checks":0,"unqueried_message_negative_tests":0,
          "checking_key_recomputations":0,"fixed_manifest_checks":0}
def check(v,descr):
    global assertions
    assertions+=1
    if not v: raise AssertionError(f"{assertions} {descr}")
def h(*args):
    x=hashlib.sha256()
    for a in args:
        z=(a if isinstance(a,bytes) else str(a).encode())
        x.update(len(z).to_bytes(4,"big"));x.update(z)
    return x.digest()
def canon(v):
    return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def stretch(root,n):
    return hashlib.shake_256(b"R81-TEST-ONLY"+root).digest(n)
def valid(pk,m,sig):
    try: pk.verify(sig,m);return True
    except InvalidSignature:return False
class SignOracle:
    def __init__(self,sk):
        self.__sk=sk; self.queries=[]
    def sign(self,m):
        self.queries.append(m)
        return self.__sk.sign(m)
def source(nibbles,seed,slot):
    A=(-1,1,1,1)
    cs=[]
    for j,word in enumerate(nibbles):
        z=h(seed,b"source",slot,j.to_bytes(2,"big"))[0]
        # zero error and q=256, Delta=16: a toy exact moment source
        cs.append(tuple((a*z+(16*word if row==0 else 0))%256
                        for row,a in enumerate(A)))
    return cs
def root_nibbles(root):
    return [(b>>4)&15 for b in root]+[b&15 for b in root]
def open_root(src,w):
    # ORIGINAL relation a+b+c=1, w in {(1,0,0),(0,1,0),(0,0,1)}.
    r=(1,)+tuple(w)
    assert sum(w)==1 and all(b in (0,1) for b in w)
    vals=[]
    for C in src:
        val=sum(x*y for x,y in zip(C,r))%256
        check(val%16==0,"genuine moment has exact nibble")
        vals.append(val//16)
    return bytes((vals[i]<<4)|vals[i+16] for i in range(16))
def manifest(pk):
    pub=pk.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    base={"relation":"ORIGINAL: a+b+c=1","claim":"outpoint:001122:4",
          "anchor":"BTC-ancestor-window:fixed","native_vk_hash":h(pub).hex(),
          "graph":"immutable N-of-N challenge/timeout graph - modeled only",
          "slots":("challenge","timeout")}
    fixed=h(b"R81-GRAPH",canon(base)).hex()
    ms=[]
    for slot in base["slots"]:
        scope={**base,"graph_digest":fixed,"branch":slot}
        ms.append((scope,h(b"native-sign",canon(scope))))
    return ms
def build(pk,sign,seed):
    scopes=manifest(pk)
    prev_ck=b"\x00"*32
    views=[]
    for i,(scope,m) in enumerate(scopes):
        k=h(seed,b"root",i.to_bytes(2,"big"))[:16]
        z=source(root_nibbles(k),seed,i)
        sig=sign(m)
        check(len(sig)==64,"Ed25519 test signature size")
        split=stretch(k,96)
        pad,B=split[:64],split[64:96]
        d=bytes(a^b for a,b in zip(sig,pad))
        scope_bytes=canon(scope)
        cbytes=canon(z)
        ck=h(b"CK",B,d,scope_bytes,cbytes,prev_ck)
        aux=h(b"AUX",B,d,ck,scope_bytes,cbytes,prev_ck)
        views.append({"scope":scope,"message":m.hex(),
             "source":z,"dsig":d.hex(),"ck":ck.hex(),"aux":aux.hex(),
             "previous_ck":prev_ck.hex()})
        prev_ck=ck
    return views
def opened(view,w,pk):
    k=open_root(view["source"],w)
    padB=stretch(k,96)
    sig=bytes(x^y for x,y in zip(bytes.fromhex(view["dsig"]),padB[:64]))
    ck=h(b"CK",padB[64:],bytes.fromhex(view["dsig"]),
         canon(view["scope"]),canon(view["source"]),
         bytes.fromhex(view["previous_ck"]))
    aux=h(b"AUX",padB[64:],bytes.fromhex(view["dsig"]),ck,
         canon(view["scope"]),canon(view["source"]),
         bytes.fromhex(view["previous_ck"]))
    check(ck.hex()==view["ck"] and aux.hex()==view["aux"],
          "whole checking-key/auxiliary DAG recomputed")
    counters["checking_key_recomputations"]+=1
    check(valid(pk,bytes.fromhex(view["message"]),sig),"legitimate native signature")
    return k,sig
W=[(1,0,0),(0,1,0),(0,0,1)]
for t in range(64):
    seed=h(b"run81-fixture",t.to_bytes(2,"big"))
    sk=Ed25519PrivateKey.from_private_bytes(h(b"sk",seed))
    pk=sk.public_key()
    oracle=SignOracle(sk)
    oview=build(pk,oracle.sign,seed)
    rview=build(pk,sk.sign,seed)
    check(canon(oview)==canon(rview),"perfect entire public-view coupling")
    counters["full_public_couplings"]+=1
    check([bytes.fromhex(v["message"]) for v in oview]==oracle.queries,
          "only manifest messages were queried")
    counters["fixed_manifest_checks"]+=1
    previous=[None,None]
    for i,v in enumerate(oview):
        for w in W:
            k,sig=opened(v,w,pk)
            check(k==h(seed,b"root",i.to_bytes(2,"big"))[:16],
                  "actual encrypted root, not alternate")
            check(previous[i] is None or previous[i]==(k,sig),
                  "distinct ORIGINAL witnesses recover same signature")
            previous[i]=(k,sig)
            counters["original_witness_openings"]+=1
            counters["same_capability_checks"]+=1
        # A signing oracle was never queried on a new outpoint/branch.
        tampered={**v["scope"],"claim":"outpoint:OTHER:4"}
        new_message=h(b"native-sign",canon(tampered))
        check(new_message not in oracle.queries,"fresh message off query list")
        check(not valid(pk,new_message,previous[i][1]),
              "old honest signature cannot authorize changed claim")
        other=bytes.fromhex(oview[1-i]["message"])
        check(not valid(pk,other,previous[i][1]),"branch swap rejected")
        counters["unqueried_message_negative_tests"]+=2
print(json.dumps({"run":RUN,"status":"RESTRICTED_TRUE_OUT_OF_SCOPE_NATIVE_EUF_REDUCTION",
  "assertions":assertions,"cases":64,"authorized_slots_per_case":2,
  "distinct_original_witnesses":len(W),"counts":counters,
  "crypto_fixture":"Ed25519 test only, not PQ; deterministic SHAKE pad is NOT a cryptographic security argument",
  "scope":"actual full-public simulator via chosen-signing-message oracle; no hard-TRUE same-message source simulation/extraction, no LWE security proof"},indent=2))
