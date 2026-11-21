from itertools import product
from math import log2
import json
q=7; A=(1,2,3,4,5); good=set(tuple(a*s%q for a in A) for s in range(q))
assert len(good)==7
count=0
for b in product(range(q),repeat=len(A)):
    valid=any(all((a*s)%q==bb for a,bb in zip(A,b)) for s in range(q))
    assert valid == (b in good)
    count+=valid
assert count==7
log_bound=(256-6800)*log2(16777213)+6800*log2(257)
assert log_bound < -100000
print(json.dumps({'status':'PASS','checked_uniform_sources':7**5,'true_sources':count,'public_test_advantage':1-count/7**5,'large_log2_false_source_bound':round(log_bound,6)},sort_keys=True))
