"""Read-only reproduction of the exact Run706 archive's public cancellation.
The attack routine receives only q and the published polynomial coefficients.
The archived setup is executed unchanged; its secrets are used only by the
separate validation stage after the public attack returns.
"""
from pathlib import Path
import contextlib, io, json, runpy, hashlib
import numpy as np
from sympy import GF
from sympy.polys.matrices import DomainMatrix
from sympy.polys.galoistools import gf_factor
from sympy.polys.domains import ZZ

ROOT=Path(__file__).resolve().parent

def field_roots_of_matrix(matrix, q):
    dm=DomainMatrix.from_list([[int(x)%q for x in row] for row in matrix],GF(q))
    cp=[int(x)%q for x in dm.charpoly()]
    _, factors=gf_factor(cp,q,ZZ)
    roots=sorted({(-int(f[1])*pow(int(f[0]),-1,q))%q for f,e in factors if len(f)==2})
    return roots,cp

def public_attack(pub):
    q=pub['q']; y=[0,0,0,1,1,1]
    out=np.array(pub['constant'],dtype=np.int64)
    for i in range(6):
        out=(out+y[i]*np.array(pub['linear'][i],dtype=np.int64)+y[i]*y[i]*np.array(pub['square'][i],dtype=np.int64))%q
    for name,mat in pub['cross'].items():
        i,j=map(int,name.split(','));out=(out+y[i]*y[j]*np.array(mat,dtype=np.int64))%q
    # Only the second gate of the first clause contains the monomial v*a1.
    # Its coefficient is exactly its constant residual mask.
    out=(out-np.array(pub['cross']['1,2'],dtype=np.int64))%q
    roots,cp=field_roots_of_matrix(out.tolist(),q)
    return {'chosen_source':y,'candidates':roots,'characteristic_polynomial':cp,'matrix':out.tolist()}

if __name__=='__main__':
    capture=io.StringIO()
    with contextlib.redirect_stdout(capture):
        ns=runpy.run_path(str(ROOT/'run706_spectral_source_binding_check.py'))
    (ROOT/'exact_archive_original_stdout.json').write_text(capture.getvalue())
    pub={'q':ns['q'],'N':ns['N'],'constant':ns['const'].tolist(),
         'linear':[m.tolist() for m in ns['lin']], 'square':[m.tolist() for m in ns['sq']],
         'cross':{f'{i},{j}':m.tolist() for (i,j),m in ns['cross'].items()}}
    # No K, mask, factors, or generation seed is passed to the attacker.
    (ROOT/'exact_run706_public.json').write_text(json.dumps(pub,sort_keys=True))
    attack=public_attack(pub)
    (ROOT/'exact_run706_attack_output.json').write_text(json.dumps(attack,sort_keys=True))
    q=ns['q']; y=tuple(attack['chosen_source']);K=ns['K'];I=ns['I']
    rs=[int((a*b-c*d)%q) for a,b,c,d in ns['gates']((1,)+y)]
    assert rs==[0,0,0,1,0,0,0,0]
    coeff_exposes=np.array_equal(ns['cross'][1,2],ns['Q'][3])
    assert coeff_exposes
    T=np.array(attack['matrix'],dtype=np.int64)
    rT=ns['rank_mod']((T-K*I)%q,q)
    rC=ns['rank_mod']((ns['public_eval'](y)-K*I)%q,q)
    assert rT<=18<ns['N']
    assert K in attack['candidates']
    result={'exact_archive_script_sha256':hashlib.sha256((ROOT/'run706_spectral_source_binding_check.py').read_bytes()).hexdigest(),
        'original_checks':ns['assertions'],'q':q,'m':ns['m'],'s':ns['s'],'N':ns['N'],
        'source':list(y),'residuals':rs,'exposed_mask_coefficient_matches_private_reference':coeff_exposes,
        'cancelled_rank_at_reference_key':rT,'point_evaluation_rank_at_reference_key':rC,
        'advertised_rank_threshold':ns['N']-ns['s'],
        'candidates':attack['candidates'],'reference_key':K,
        'reference_key_in_candidates':K in attack['candidates'],
        'random_candidate_success_lower_bound':f"1/{len(attack['candidates'])}",
        'factorization_without_field_enumeration':True,
        'attack_input_contains_key_or_seed_or_factors':False,
        'scope':'Synthetic q=101 archived setup; no standard signature scheme or production system attacked.'}
    print(json.dumps(result,indent=2,sort_keys=True))
