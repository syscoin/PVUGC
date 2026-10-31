#!/usr/bin/env python3
"""Exact finite counts for false signed-unit AND-source pseudo-opening."""
from fractions import Fraction
import json
rows=[]; checks=0
for k in (1,2,4,8,16,32):
    bad=[-1,1,1]+[-3,-1,1]*k
    good=[1,1,1]+[-1,-1,-1]*k
    m=len(bad); g=2*(m+1)+1
    assert len(good)==m and m+1<g/2;checks+=1
    for j in range(k):
        i=3+3*j
        assert bad[0]-bad[2]-bad[i]==1;checks+=1
        assert bad[1]-bad[2]-bad[i+1]==1;checks+=1
        assert bad[0]+bad[1]-bad[2]+bad[i+2]==0;checks+=1
        assert good[0]-good[2]-good[i]==1;checks+=1
        assert good[1]-good[2]-good[i+1]==1;checks+=1
        assert good[0]+good[1]-good[2]+good[i+2]==0;checks+=1
    assert bad[3]==-3 and all(v in (-1,1) for v in good);checks+=1
    counts={0:1}
    for a in bad+[1]:
        tmp={}
        for s,n in counts.items():
            for e in (-1,0,1):tmp[s+a*e]=tmp.get(s+a*e,0)+n
        counts=tmp
    total=3**(m+1)
    assert sum(counts.values())==total;checks+=1
    ok=sum(n for s,n in counts.items() if 2*abs(s)<g)
    rows.append({'k':k,'m':m,'g':g,'success_exact':str(Fraction(ok,total)),'success_float':float(Fraction(ok,total))})
print(json.dumps({'status':'pass','assertions':checks,'results':rows},sort_keys=True,indent=2))
