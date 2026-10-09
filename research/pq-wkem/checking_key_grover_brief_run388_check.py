#!/usr/bin/env python3
"""Run 388 EXACT published checker: toy checking-key/Grover oracle, not a WKEM."""
import hashlib, json, math
H = lambda x: hashlib.sha256(x).digest()
KEY = H(b"run388/toy/release/seed")
MSG = 11  # toy 4-bit context; NOT a Bitcoin sighash
pk = lambda k: tuple(H(H(k+bytes((i,j)))) for i in range(4) for j in range(2))
sign = lambda k: tuple(H(k+bytes((i,(MSG>>i)&1))) for i in range(4))
verify = lambda key, sig: all(H(sig[i]) == key[2*i+((MSG>>i)&1)] for i in range(4))
VK = pk(KEY)
assert verify(VK,sign(KEY))
wrong = H(b"run388/wrong")
assert not verify(VK,sign(wrong))
assert (wrong,VK)[1] == VK  # copying embedded vk is NOT native signing
checks, fixtures = 0, []
for b in range(4,7):
    N=1<<b
    for M in (1,2,3,5):
        inv5 = pow(5,-1,N)
        F = lambda s: (KEY if (inv5*(s-3))%N < M else H(b"decoy"+s.to_bytes(2,"little")))
        marked = [verify(VK,sign(F(s))) for s in range(N)]
        assert sum(marked)==M
        checks+=1
        for w in range(M):
            assert F((5*w+3)%N)==KEY
            checks+=1
        v=[1/math.sqrt(N)]*N
        theta=math.asin(math.sqrt(M/N))
        for r in range(5):
            observed=sum(v[s]**2 for s in range(N) if marked[s])
            expected=math.sin((2*r+1)*theta)**2
            assert abs(observed-expected)<1e-11
            checks+=1
            v=[-x if marked[s] else x for s,x in enumerate(v)]
            mean=sum(v)/N
            v=[2*mean-x for x in v]
        fixtures.append({"b":b,"distinct_valid_states":M,"marked_fraction":M/N})
print(json.dumps({"run":388,"status":"PASS","checks":checks,
                  "finite_fixtures":len(fixtures),"fixtures":fixtures,
                  "bottom_flag":False,"success_predicate":"toy hash-based native Sign+Verify",
                  "real_SlhDsa":False,"real_WKEM":False,"QPT_security":False},sort_keys=True))
