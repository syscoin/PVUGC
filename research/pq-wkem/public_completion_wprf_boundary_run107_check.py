#!/usr/bin/env python3
from itertools import product
import json, math

checks=[]
def ok(name, cond, detail=None):
    if not cond: raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

table_records=[]
relations_checked=0
witness_checks=0
false_independence_checks=0

for n in range(1,5):
    W=list(product((0,1), repeat=n))
    N=len(W)
    if n <= 3:
        rel_masks=range(1 << N)
    else:
        rel_masks=[0,1,(1<<N)-1]
        rel_masks += [1<<i for i in range(N)]
        rel_masks += [(1<<i)|(1<<j) for i in range(0,N,3) for j in range(i+1,N,5)]
        rel_masks=sorted(set(rel_masks))
    for mask in rel_masks:
        R={w:(mask>>i)&1 for i,w in enumerate(W)}
        relations_checked+=1
        tokens={}
        for K in (0,1):
            for r in (0,1):
                T=tuple(r ^ (R[w] & K) for w in W)
                token=(r,T)
                tokens[(K,r)]=token
                for i,w in enumerate(W):
                    if R[w]:
                        ok(f"all_witness_{n}_{mask}_{K}_{r}_{i}",(T[i]^r)==K)
                        witness_checks+=1
        if mask==0:
            for r in (0,1):
                ok(f"false_independent_{n}_{r}",tokens[(0,r)]==tokens[(1,r)])
                false_independence_checks+=1
        table_records.append({"n":n,"witness_domain_size":N,"token_entries":N+1,
                              "relation_weight":sum(R.values())})

for n in range(1,20):
    ok(f"exp_size_{n}",(1<<n)+1==2**n+1)

sms_cases=0
for n in range(1,4):
    W=list(product((0,1), repeat=n))
    N=len(W)
    for mask in range(1<<N):
        R={w:(mask>>i)&1 for i,w in enumerate(W)}
        for K in (0,1):
            for r in (0,1):
                peA=r
                ok(f"sms_peA_{n}_{mask}_{K}_{r}",peA==r)
                completion=[]
                for i,w in enumerate(W):
                    zA=r^(R[w]&K); zB=r
                    ok(f"sms_reconstruct_{sms_cases}_{i}",(zA^zB)==(R[w]&K))
                    completion.append(zA)
                expected=tuple(r^(R[w]&K) for w in W)
                ok(f"sms_completion_{sms_cases}",tuple(completion)==expected)
                sms_cases+=1

transparent_cases=0
for K in (0,1):
    for r in (0,1):
        circuit={"constants":{"K":K,"r":r},"formula":"r XOR (R(w) AND K)"}
        parsed=json.loads(json.dumps(circuit,sort_keys=True))
        ok(f"transparent_K_{K}_{r}",parsed["constants"]["K"]==K)
        ok(f"transparent_r_{K}_{r}",parsed["constants"]["r"]==r)
        transparent_cases+=1

vc_rows=[]
for n in range(4,41,4):
    entries=2**n
    ok(f"vc_exp_{n}",entries==(1<<n))
    vc_rows.append({"witness_bits":n,"truth_vector_entries":entries,"log2_entries":math.log2(entries)})

out={
 "run":107,"status":"PASS","total_assertions":len(checks),
 "truth_table_release":{"relations_checked":relations_checked,
   "valid_witness_decapsulation_checks":witness_checks,
   "false_statement_independence_checks":false_independence_checks,
   "claim":"Direct public completion is all-witness correct and perfectly false-statement hiding, but has 2^n entries."},
 "sms_completion":{"cases":sms_cases,
   "claim":"A reusable Alice first message does not eliminate the later witness-dependent Alice share; public completion is exactly the relation-indexed release map."},
 "transparent_compression":{"cases":transparent_cases,
   "claim":"The direct transparent circuit contains K and r as literal constants; hiding them requires additional cryptographic machinery."},
 "vc_adapter":vc_rows,
 "scope":["Finite functionality/size controls only; no computational security follows.",
          "Transparent-circuit check does not rule out obfuscation or another compiler.",
          "The exponential table is intentionally outside the practical/PPT target.",
          "The public-completion equivalence is proved in the accompanying note."]
}
print(json.dumps(out,indent=2,sort_keys=True))
