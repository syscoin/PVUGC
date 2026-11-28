#!/usr/bin/env python3
"""Exact selective-vs-adaptive exposure experiment. NOT FE or source WKEM."""
import hashlib,json
N=2**16
selected=int.from_bytes(hashlib.sha256(b'public fixed toy selector 2026-11-22').digest()[:2],'big')
selective_exposure_count=sum(1 for tau in range(N) if tau==0)
adaptive_exposure_count=sum(1 for tau in range(N) if tau==tau)
assert selective_exposure_count==1
assert adaptive_exposure_count==N
print(json.dumps({
 'scope':'exact selective/adaptive quantifier regression only; no FE, no Bitcoin source certificate',
 'activation_domain':N,
 'fixed_prechosen_activation':0,
 'selective_exposure_count':selective_exposure_count,
 'adaptive_exposure_count':adaptive_exposure_count,
 'selective_probability':f'{selective_exposure_count}/{N}',
 'adaptive_probability':f'{adaptive_exposure_count}/{N}',
 'example_public_selector':selected,
 'fe_implementation':False,
 'original_release_achieved':False
},sort_keys=True,indent=2))
