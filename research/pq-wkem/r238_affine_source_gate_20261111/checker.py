#!/usr/bin/env python3
"""R238: finite-field interpolation only, NOT WKEM or consensus validation."""
import hashlib,json,itertools
P=65537
def H(domain,data):
    s=domain+b'\0'+len(data).to_bytes(2,'big')+data
    return int.from_bytes(hashlib.sha256(s).digest(),'big')%P
def share(K,a,x):return (K+a*x)%P
def interpol(x,sx,y,sy):
    assert x!=y
    return ((y*sx-x*sy)*pow(y-x,P-2,P))%P
pairs=early=api=0
for seed in range(12):
    K=H(b'K',bytes([seed]));a=H(b'slope',bytes([seed])) or 1
    xs=[]
    for i in range(32):
        x=H(b'parent',b'parent-coinbase-commitment|'+i.to_bytes(4,'big'))
        if x not in xs:xs.append(x)
    assert len(xs)>=30
    for x,y in itertools.combinations(xs,2):
        assert interpol(x,share(K,a,x),y,share(K,a,y))==K
        pairs+=1
    fake=[H(b'parent',b'unmined-fabricated-'+i.to_bytes(2,'big')) for i in range(2)]
    assert fake[0]!=fake[1]
    assert interpol(fake[0],share(K,a,fake[0]),fake[1],share(K,a,fake[1]))==K
    early+=1
    def honest_open(records):
        if not all(record['authenticated'] for record in records): return None
        if len(records)!=2 or records[0]['point']==records[1]['point']:return None
        return interpol(records[0]['point'],records[0]['share'],records[1]['point'],records[1]['share'])
    assert honest_open([{'point':fake[0],'share':share(K,a,fake[0]),'authenticated':False},
                        {'point':fake[1],'share':share(K,a,fake[1]),'authenticated':False}]) is None
    api+=1
print(json.dumps({'run':'R238','valid_pair_correctness_checks':pairs,
'fake_raw_share_early_recovery_cases':early,'honest_api_rejection_cases':api,
'test_model':'finite-field algebra, synthetic IDs, raw share interface',
'result':'universal interpolation correct but source gate not instantiated'},indent=2,sort_keys=True))
