#!/usr/bin/env python3
"""R101 exact tape cardinality and exhaustive small-noise two-bit decode; offline.
Does NOT test QPT assumptions or arbitrary ORIGINAL NP extraction.
"""
import itertools, json, math
q,m,d,ell,beta,limit=65521,1656,256,16,3,2729
assert q==65521 and q//4==16380
checks=0

def support(rows):
    dp=[1]+[0]*limit
    for _ in range(rows):
        nxt=[0]*(limit+1)
        for j in range(limit+1):
            nxt[j]=dp[j]+2*sum(dp[max(0,j-3):j])
        dp=nxt
    return sum(dp)

def log2int(x):
    z=max(0,x.bit_length()-53)
    return math.log2(x>>z)+z

s0,s1=support(m-1),support(m)
checks+=1;assert s1>s0>0
G=16*16*math.ceil(11008/(2*ell))
def log_error(s):return math.log2(G)-1+((d+ell)*math.log2(q)-log2int(s))/2
checks+=1;assert log_error(s0)>-128 and log_error(s1)<-128
D=q//4;dist=min(D,q-3*D)
checks+=1;assert beta*limit==8187 and 2*beta*limit<dist
checks+=1;assert math.ceil(11008/ell)==688 and math.ceil(11008/(2*ell))==344
old_pk=1649*(d+16*ell)*2;new_pk=m*(d+16*ell)*2
old_ct=688*(d+ell)*2;new_ct=344*(d+ell)*2
checks+=1;assert (old_pk,new_pk,old_ct,new_ct)==(1688576,1695744,374272,187136)
# A true source leaf has B=AS+E; subtracting secret leaves only r.E.
# Exhaust ALL 4-dimensional toy error vectors and allowed coin vectors.
qtoy=257; delta=qtoy//4; tapes=0
for r in itertools.product(range(-3,4),repeat=4):
    if sum(map(abs,r))>7:continue
    tapes+=1
    for e in itertools.product((-1,0,1),repeat=4):
        noise=sum(x*y for x,y in zip(r,e))
        for bitpair in range(4):
            z=(delta*bitpair+noise)%qtoy
            got=min(range(4),key=lambda a:min((z-a*delta)%qtoy,(a*delta-z)%qtoy))
            checks+=1;assert got==bitpair
result={'run':'R101-BOUNDED-L1-TWO-BIT-SAME-Q-20261105',
        'status':'RESTRICTED_EFFICIENCY_NOT_GENERIC_NP',
        'assertions':checks,'toy_tapes':tapes,
        'q':q,'m':m,'d':d,'ell':ell,'beta':beta,'L1_limit':limit,
        'log2_support':log2int(s1),
        'rejection_acceptance_probability':2**(log2int(s1)-m*math.log2(7)),
        'false_groups':G,'log2_full_false_LHL_upper':log_error(s1),
        'log2_m_minus_1_LHL_upper':log_error(s0),
        'worst_noise':beta*limit,'cyclic_code_gap':dist,
        'old_pk_bytes':old_pk,'new_pk_bytes':new_pk,
        'old_leaf_ct_bytes':old_ct,'new_leaf_ct_bytes':new_ct,
        'net_bytes_saved_one_16_leaf_capsule':16*(old_ct-new_ct)-(new_pk-old_pk),
        'warning':'QPT decisional LWE is an uncalibrated assumption; toy algebra is not QPT security'}
print(json.dumps(result,indent=2))
