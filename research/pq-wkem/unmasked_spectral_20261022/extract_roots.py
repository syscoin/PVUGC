"""Recover key candidates from a PUBLIC attacker-constructed spectral polynomial.
Does not read the setup key or the private factor matrices.
"""
import argparse
import hashlib
import json
from pathlib import Path
from time import perf_counter
from sympy.polys.galoistools import gf_pow_mod, gf_sub, gf_gcd, gf_factor
from sympy.polys.domains import ZZ

def recover(record):
    p=int(record['q'])
    f=[int(v) for v in record['polynomial_low_to_high'][::-1]]
    start=perf_counter()
    # Isolate F_p roots without factoring the remaining high-degree factors.
    g=gf_gcd(f,gf_sub(gf_pow_mod([1,0],p,f,p,ZZ),[1,0],p,ZZ),p,ZZ)
    _,factors=gf_factor(g,p,ZZ)
    roots=sorted({(-int(h[1])*pow(int(h[0]),-1,p))%p for h,e in factors if len(h)==2})
    tag=record['public_key_tag_sha3_512']
    matching=[k for k in roots if hashlib.sha3_512(('unmasked-spectral-test:'+str(k)).encode()).hexdigest()==tag]
    h=[int(v) for v in record['structural_matrix_minpoly_low_to_high'][::-1]]
    derivative=[h[i]*(len(h)-1-i)%p for i in range(len(h)-1)]
    squarefree=len(gf_gcd(h,derivative,p,ZZ))==1
    return {'field_bits':p.bit_length(),'N':record['N'],'block_size':record['block'],
            'polynomial_degree':len(f)-1,'field_root_count':len(roots),
            'matching_keys':[str(k) for k in matching],
            'structural_minpoly_degree':len(h)-1,
            'structural_minpoly_squarefree':squarefree,
            'field_enumeration':False,'witness_supplied':False,'setup_factors_supplied':False,
            'root_extraction_seconds':perf_counter()-start}

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('public_record');a.add_argument('--output');ns=a.parse_args()
    result=recover(json.loads(Path(ns.public_record).read_text()))
    text=json.dumps(result,indent=2,sort_keys=True)+'\n'
    print(text,end='')
    if ns.output:Path(ns.output).write_text(text)
