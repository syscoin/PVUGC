"""Bounded deterministic validation; stdout is a reproducible JSON record.
Requires Python 3 and NumPy. No security is inferred from these tests.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import random
from pathlib import Path
import numpy as np
from frobenius_qap import (Field, compile_qap, gate, setup, evaluate, peval, pmul,
                          padd, pscale, candidates, tag, pencil_diagnostic)

checks = 0

def check(condition, message='check failed'):
    global checks
    checks += 1
    if not bool(condition):
        raise AssertionError(message)


def source(name):
    if name == 'product_zero':
        # u^2=u, v^2=v, u*v=0: exactly three Boolean witnesses.
        return ([[0,1,0],[0,0,1],[0,1,0]],
                [[0,1,0],[0,0,1],[0,0,1]],
                [[0,1,0],[0,0,1],[0,0,0]])
    if name == 'false':
        # x^2=x, x=0, x=1: no witness in any characteristic-two field.
        return ([[0,1],[0,1],[0,1]],
                [[0,1],[1,0],[1,0]],
                [[0,1],[0,0],[1,0]])
    if name == 'nand_accept':
        # All three wires Boolean; w = NAND(u,v); w=1.
        return ([[0,1,0,0],[0,0,1,0],[0,0,0,1],[0,1,0,0],[0,0,0,1]],
                [[0,1,0,0],[0,0,1,0],[0,0,0,1],[0,0,1,0],[1,0,0,0]],
                [[0,1,0,0],[0,0,1,0],[0,0,0,1],[1,0,0,1],[1,0,0,0]])
    raise ValueError(name)


def all_residuals(comp, Y):
    f = comp.field
    L, k, _ = comp.forms.shape
    forms = comp.forms.transpose(1, 0, 2).reshape(k, L * 5)
    vals = f.mm(Y, forms).reshape(len(Y), L, 5)
    res = f.table[vals[:,:,0], vals[:,:,1]] ^ f.table[vals[:,:,2], vals[:,:,3]] ^ f.table[vals[:,:,4], vals[:,:,4]]
    return vals, res


def main():
    f4, f8, f256 = Field(2, 0b111), Field(3, 0b1011), Field(8, 0x11b)
    rejected = False
    try:
        Field(3, 0b1001)
    except ValueError:
        rejected = True
    check(rejected)
    field_rows = []
    for f in (f4, f8, f256):
        for a in range(f.q):
            check(f.mul(f.roots[a], f.roots[a]) == a)
            if a:
                check(f.mul(a, f.inverse(a)) == 1)
        field_rows.append(dict(q=f.q, modulus=f.modulus, irreducibility_checked=True))
    gate_counts = {'rank_0':0,'rank_2':0,'rank_4':0}
    for vals in itertools.product(range(4), repeat=5):
        a,b,c,d,s = vals
        p = gate(*vals)
        residual = f4.mul(a,b) ^ f4.mul(c,d) ^ f4.mul(s,s)
        expected = 4 if residual else (2 if any(vals) else 0)
        check(f4.rank(p) == expected)
        check(f4.determinant(p) == f4.mul(residual,residual))
        gate_counts[f'rank_{expected}'] += 1
    source_rows = []
    for name in ('product_zero','false'):
        comp = compile_qap(f8,*source(name))
        k = comp.forms.shape[1]
        vectors = list(itertools.product(range(8), repeat=k-1))
        Y1 = np.array([[1,*v] for v in vectors], dtype=np.uint16)
        Y0 = Y1.copy();Y0[:,0] = 0
        _, res1 = all_residuals(comp,Y1)
        _, res0 = all_residuals(comp,Y0)
        yes1 = Y1[np.all(res1 == 0, axis=1)]
        yes0 = Y0[np.all(res0 == 0, axis=1)]
        check(len(yes1) == (3 if name == 'product_zero' else 0))
        check(len(yes0) == 1 and not np.any(yes0[0]))
        originals = []
        for y in yes1:
            z = list(map(int,y))
            original = comp.extract(z)
            check(comp.encode(original) == z)
            originals.append(original)
            for scalar in range(1,8):
                scaled = [f8.mul(scalar,v) for v in z]
                check(not any(comp.residuals(scaled)))
                check(comp.extract(scaled) == original)
        # Matched negative control: the previous homogeneous z0*H encoding
        # accepts every pure quotient direction at z0=0. The new one accepts none.
        old_bad = new_bad = 0
        for h in itertools.product(range(8),repeat=comp.rows-1):
            if not any(h):
                continue
            y = [0]*comp.base+list(h)
            old_bad += 1 # old A=B=C=z0=0 makes every old residual identically zero
            new_bad += not any(comp.residuals(y))
        check(old_bad == 8**(comp.rows-1)-1 and new_bad == 0)
        source_rows.append(dict(name=name,field=8,normalized_assignments=len(Y1),
            infinity_assignments=len(Y0),normalized_accepted=len(yes1),
            nonzero_infinity_accepted=0,old_pure_quotient_infinity=old_bad,
            new_pure_quotient_infinity=new_bad,original_witnesses=originals))
    comp = compile_qap(f8,*source('product_zero'))
    k = comp.forms.shape[1];L = len(comp.forms)
    Y = np.array(list(itertools.product(range(8), repeat=k)),dtype=np.uint16)[1:]
    vals, res = all_residuals(comp,Y)
    supports = np.count_nonzero(np.any(vals != 0,axis=2),axis=1)
    check(np.all(supports >= L-comp.rows+1))
    gate_ranks = np.where(np.any(vals != 0,axis=2),np.where(res == 0,2,4),0)
    total_ranks = gate_ranks.sum(axis=1)
    check(np.all(total_ranks >= 2*(L-comp.rows+1)))
    support_result = dict(nonzero_directions=len(Y),minimum_support=int(supports.min()),
        promised_support=L-comp.rows+1,minimum_block_diagonal_rank=int(total_ranks.min()),
        promised_rank=2*(L-comp.rows+1))
    comp = compile_qap(f256,*source('nand_accept'))
    witnesses = []
    for bits in itertools.product((0,1),repeat=3):
        try:
            y = comp.encode(bits)
            witnesses.append((list(bits),y))
        except ValueError:
            check(bits not in ((0,0,1),(0,1,1),(1,0,1)))
    check(len(witnesses) == 3)
    spectral = []
    pencils = []
    context = b'QAP-FROBENIUS-RESEARCH-ONLY/claim-A/challenge'
    for seed in (17,29,41):
        key = random.Random(seed ^ 0x1234).randrange(256)
        public, factors = setup(comp,key,seed)
        N = len(public[0]);expected_tag=tag(context,key)
        digest_set = set()
        for index,(bits,y) in enumerate(witnesses):
            mat = evaluate(f256,public,y)
            baseline = mat ^ f256.table[key,np.eye(N,dtype=np.uint16)]
            check(f256.rank(baseline) <= 2*len(comp.forms))
            ref = np.zeros_like(mat)
            for forms,(left,right) in zip(comp.evaluate_forms(y),factors):
                check(f256.rank(gate(*forms)) == 2)
                ref ^= f256.mm(f256.mm(left,gate(*forms)),right)
            check(np.array_equal(ref,baseline))
            roots = candidates(f256,mat,seed=seed*100+index)
            selected = [r for r in roots if tag(context,r)==expected_tag]
            check(selected == [key])
            check(not any(tag(context+b'/other',r)==expected_tag for r in roots))
            digest_set.add(hashlib.sha256(mat.tobytes()).hexdigest())
            spectral.append(dict(seed=seed,witness=bits,N=N,field_roots=roots,
                                 key=key,selected=selected,nullity=N-f256.rank(baseline)))
        check(len(digest_set)==3)
        rng=random.Random(seed+101)
        for _ in range(6):
            y=[rng.randrange(256) for _ in range(comp.forms.shape[1])]
            reference=np.zeros((N,N),dtype=np.uint16)
            for forms,(left,right) in zip(comp.evaluate_forms(y),factors):
                reference ^= f256.mm(f256.mm(left,gate(*forms)),right)
            reference ^= f256.table[f256.mul(key,y[0]),np.eye(N,dtype=np.uint16)]
            check(np.array_equal(evaluate(f256,public,y),reference))
        for indices in ((1,2,3),(4,5,6)):
            pencils.append(dict(seed=seed,**pencil_diagnostic(f256,public,key,indices)))
    # The new scalar block fixes a representation gap, not a hiding theorem.
    m=comp.rows;n=comp.base-1;L=2*m-1;k=n+m;N=2*L+1
    size=dict(n=n,m=m,L=L,coefficient_matrices=k,N=N,
              dense_field_elements=k*N*N,dense_payload_bits=k*N*N*8,
              prior_scalar_qap_field_elements=(n+m)*(2*(2*m-1)+1)**2,
              extra_source_variables=0,extra_evaluation_gates=0,
              minimum_alternating_block_dimension=4,
              excludes_metadata_native_keys_tags_and_setup_proofs=True)
    check(size['dense_field_elements']==size['prior_scalar_qap_field_elements'])
    # Functional all-witness and projective claims survive arbitrary postprocessing;
    # these regression probes are NOT a quantified computational-security test.
    result = dict(checkpoint='qap-frobenius-projective-20261022',
        status='COMPILER_COMPONENT_ONLY_NOT_QPT_SECURITY',
        fields=field_rows,gate_census=dict(tuples=4**5,**gate_counts),
        source_censuses=source_rows,all_direction_check=support_result,
        spectral_recoveries=spectral,internal_pencil_diagnostics=pencils,size=size,
        assertions=checks,
        code_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (Path(__file__),Path(__file__).with_name('frobenius_qap.py'))})
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
