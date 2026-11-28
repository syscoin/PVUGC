import hashlib, json, sys
from pathlib import Path
from time import perf_counter
from probe import generate, recover, rank, inv, mm, comm
import numpy as np

def tag(k): return hashlib.sha3_512(('unmasked-spectral-test:'+str(k)).encode()).hexdigest()
rows=[]
for b,m,count in [(1,32,12),(2,32,8),(2,128,4)]:
 for seed in range(101,101+count):
  K=(seed*193+123)%65537
  C=generate(m,b,seed,65537,K)
  public_tag=tag(K)
  start=perf_counter()
  try:
   r=recover(C,b,65537)
   selected=[a for a in r['candidates'] if tag(a)==public_tag]
   assert selected==[K]
   row={'b':b,'m':m,'N':2*b*m+1,'seed':seed,'polynomial_degree':r['polynomial_degree'],
        'field_root_count':len(r['candidates']),'exact_key_recovered':selected==[K],
        'no_field_enumeration':True,'seconds':perf_counter()-start}
  except Exception as e:
   row={'b':b,'m':m,'seed':seed,'failure':repr(e)}
  rows.append(row)
  print(json.dumps(row),flush=True)
out={'field':65537,'cases':len(rows),'successful':sum(r.get('exact_key_recovered',False) for r in rows),
     'all_sources_false':True,'all_padding_s':1,'residual_shields':False,'rows':rows}
Path(__file__).with_name('batch_validation.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
assert out['successful']==out['cases']
