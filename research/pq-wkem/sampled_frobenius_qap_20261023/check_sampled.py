"""Finite-field construction and soundness regression: not a KEM security test."""
from __future__ import annotations
# Exact predecessor dependency; refuse silently substituted algebra.
from pathlib import Path
import hashlib, sys
PREVIOUS = Path(__file__).resolve().parents[1] / 'qap_frobenius_projective_20261022' / 'frobenius_qap.py'
EXPECTED_PREVIOUS_SHA256 = '6da9e9519c1f9b21d00b736679ba498cb56a7518e9610abc7934ec3aacf66d9a'
if not PREVIOUS.exists() or hashlib.sha256(PREVIOUS.read_bytes()).hexdigest() != EXPECTED_PREVIOUS_SHA256:
    raise RuntimeError('missing or modified exact prior Frobenius-QAP dependency')
sys.path.insert(0, str(PREVIOUS.parent))
import hashlib
import itertools
import math
import json
from pathlib import Path
import random

import numpy as np

from frobenius_qap import Field, setup, evaluate, candidates, tag
from sampled_qap import (compile_sampled, uniquely_interpolate_quotient,
                         exact_union_bound, integer_union_bound_exponent,
                         residual_interpolant, certified_extra_checks)

assertions=0

def check(condition, msg='failed check'):
    global assertions
    assertions+=1
    if not bool(condition):
        raise AssertionError(msg)


def repeated_booleanity(contradiction:bool=False):
    # m=6, n=1: x^2 = z0*x. Valid instances accept BOTH x=0,1.
    # False control additionally imposes x=0 and x=1 simultaneously.
    # The rows are a COMPLETE homogeneous source, including Booleanity.
    A=[];B=[];C=[]
    for _ in range(4 if contradiction else 6):
        A.append([0,1]);B.append([0,1]);C.append([0,1])
    if contradiction:
        A.extend(([0,1],[0,1]));B.extend(([1,0],[1,0]));C.extend(([0,0],[1,0]))
    return [np.array(x,dtype=np.uint16) for x in (A,B,C)]


def original_accepted(comp,z):
    f=comp.field
    A,B,C=comp.source
    for a,b,c in zip(A,B,C):
        if f.mul(f.dot(a,z),f.dot(b,z)) != f.mul(z[0],f.dot(c,z)):
            return False
    return True


def census_projective(comp):
    f=comp.field
    # All q affine classes (1,x), plus one class at infinity (0,1).
    zlist=[[1,x] for x in range(f.q)]+[[0,1]]
    accepted=[]; invalid=[]
    for z_index,z in enumerate(zlist):
        y=uniquely_interpolate_quotient(comp,z)
        first=comp.residuals(y)[:comp.rows-1]
        check(not any(first),'quotient is not unique interpolation')
        if z_index in (0,1,2,3,16,128,f.q):
            check(certified_extra_checks(comp,z),'residual interpolant != tail checks')
        if not any(comp.residuals(y)):
            accepted.append(z)
            if not original_accepted(comp,z):
                invalid.append(z)
        elif original_accepted(comp,z):
            raise AssertionError('all-original-witness correctness failed')
    check(not invalid,'projective soundness failed on this fixture')
    # Pure quotient class z=0 has unique H=0 already after first m-1 nodes.
    check(not any(uniquely_interpolate_quotient(comp,[0,0])))
    return dict(projective_classes=len(zlist),accepted_original_sources=accepted,
                invalid_accepted=invalid)


def main():
    f=Field(8,0x11b);q=f.q
    n,m,r=1,6,3
    L=m-1+r
    oldL=2*m-1
    priorN=2*oldL+1
    N=2*L+1
    check(L<oldL)
    bad=exact_union_bound(n,m,r,q)
    check(0<bad<1)
    # Compiler's soundness failure is a GLOBAL over-all-source setup event;
    # All first m-1 evaluation nodes are fixed; only the final r are random.
    # Twenty sampled source fixtures are regression checks, not the proof.
    rows=[]
    for name in ('true','false'):
        for j in range(10):
            seed=10000*j+(0 if name=='true' else 1)
            comp=compile_sampled(f,*repeated_booleanity(name=='false'),r,
                                 random.Random(seed))
            row=census_projective(comp)
            check(row['accepted_original_sources']==([[1,0],[1,1]] if name=='true' else []))
            if j in (0,1,2):
                rows.append(dict(source=name,seed=seed,eval_nodes=list(comp.eval_nodes),**row))
    comp=compile_sampled(f,*repeated_booleanity(False),r,random.Random(91911))
    # Independently compute linear support/ranks of all SOURCE coefficient directions.
    L,k,_=comp.forms.shape
    check((L,k,N)==(8,7,17))
    base=[0]*k
    for idx in range(k):
        base[idx]=1
        forms=comp.evaluate_forms(base)
        cnt=sum(bool(any(x)) for x in forms)
        check(cnt>=r)
        base[idx]=0
    # Pair of different ORIGINAL witnesses, one SAME capability, multiple setups.
    recovery=[]
    context=b'FROBENIUS-SAMPLED-RESEARCH/UTXO-A/branch-disprove'
    for seed in (7,31,67):
        key=random.Random(seed+500).randrange(q)
        public,factors=setup(comp,key,seed)
        paths=[]
        for x in (0,1):
            y=comp.encode([x])
            check(not any(comp.residuals(y)))
            check(comp.extract(y)==[x])
            C=evaluate(f,public,y)
            baseline=C^f.table[key,np.eye(N,dtype=np.uint16)]
            check(f.rank(baseline)<=2*L)
            roots=candidates(f,C,seed+100*x,attempts=6)
            matches=[u for u in roots if tag(context,u)==tag(context,key)]
            check(matches==[key])
            paths.append(dict(witness=x,roots=roots,selected=matches,
                              matrix_sha256=hashlib.sha256(C.tobytes()).hexdigest()))
        check(paths[0]['matrix_sha256']!=paths[1]['matrix_sha256'])
        recovery.append(dict(seed=seed,capability=key,paths=paths))
    # A conservative 128-bit compiler-soundness parameter illustration; this
    # calculation makes NO cryptographic-security claim about the public array.
    large_n,large_m,kappa,lam=11000,16000,256,128
    # Exact integer, not a floating log2 approximation: two adjacent r.
    # Monotonicity of the product bound makes this a certified minimum.
    qlarge=1<<kappa
    projective_lines=(qlarge**(large_n+1)-1)//(qlarge-1)
    def exact_128_certificate(r):
        numerator=(projective_lines*(large_m-1)**r)<<lam
        denominator=math.prod(qlarge-2*large_m+2-j for j in range(1,r+1))
        return numerator<=denominator
    rlarge=11636
    check(not exact_128_certificate(rlarge-1))
    check(exact_128_certificate(rlarge))
    r_bound=integer_union_bound_exponent(large_n,large_m,rlarge,kappa)
    # The conservative integer log bound can be looser than exact certification.
    Lold=2*large_m-1
    Lnew=large_m-1+rlarge
    payloadold=(large_n+large_m)*(2*Lold+1)**2
    payloadnew=(large_n+large_m)*(2*Lnew+1)**2
    check(0<rlarge<large_m and payloadnew<payloadold)
    out={
      'checkpoint':'sampled-frobenius-qap-20261023',
      'status':'COMPILER_SOUNDNESS_PROVED_UNDER_HONEST_NODE_SAMPLING_ONLY',
      'field_q':q,'m':m,'n':n,'r':r,'L':L,'previous_L':oldL,
      'source_matrix_dim':N,'previous_source_matrix_dim':priorN,
      'bound_failure_numerator':bad.numerator,'bound_failure_denominator':bad.denominator,
      'deterministic_base_nodes':list(range(m,2*m-1)),
      'uniform_sampled_tail_nodes':r,
      'example_expected_failure_log2_lt':str(float(bad)),
      'honest_source_census_fixtures':rows,
      'exact_census_samples_per_source':10,
      'same_capability_recovery':recovery,
      'large_example':{
        'kappa':kappa,'n':large_n,'m':large_m,'r':rlarge,
        'L_new':Lnew,'L_prior':Lold,
        'exact_integer_128bit_soundness_certificate':True,
        'exact_minimum_extra_nodes_for_this_bound':rlarge,
        'conservative_log2_upper_bound_exponent':r_bound,
        'old_field_elements':payloadold,
        'new_field_elements':payloadnew,
        'relative_matrix_payload_saving':1-payloadnew/payloadold,
        'important':'not a QPT ciphertext-hiding security bound'
      },
      'assertions':assertions,
      'files_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (Path(__file__),Path(__file__).with_name('sampled_qap.py'))},
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
