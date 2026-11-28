import hashlib, json, random

def par(x): return x.bit_count() & 1

def dist(n, a, b):
    N=n+1; M=1<<N; fibers={}
    for z in range(M):
        v=(b if z>>n else a)[z&((1<<n)-1)]
        fibers.setdefault(v,[]).append(z)
    nums=[]
    for y in range(M):
        nums.append(sum(sum(1-2*par(y&z) for z in zs)**2 for zs in fibers.values()))
    assert sum(nums)==M*M
    return nums, M*M

checks=0; fixtures=[]
for n in (3,4,5,6):
    for k in (1,2):
        M=1<<n; d=(k*7)%M or 1
        p=list(range(M)); random.Random(463+n*17+k).shuffle(p)
        f=[p[z^d] for z in range(M)]
        assert len(set(p))==len(set(f))==M; checks+=1
        period=(1<<n)|d
        nums,den=dist(n,p,f)
        for y,v in enumerate(nums):
            assert v==(den//M if par(y&period)==0 else 0)
            checks+=1
        # Public output-label derangement removes this direct period bias.
        L=lambda a:(a+1)%M
        mis=[L(v) for v in f]
        nums2,den2=dist(n,p,mis)
        assert 2*sum(v for y,v in enumerate(nums2) if par(y&period)==0)==den2
        checks+=1
        norm=[(v-1)%M for v in mis]
        assert dist(n,p,norm)==(nums,den); checks+=1
        fixtures.append({'n':n,'delta':d,'qpt_supported_mass':'1','derangement_mass':'1/2'})
print(json.dumps({'run':463,'assertions':checks,'fixtures':fixtures,'model':'exact Fourier amplitudes, no quantum hardware/PQ implementation'},sort_keys=True))
