#!/usr/bin/env python3
"""Exact full-joint classical finite census for R106 single-target PRG-hybrid.
A bounded toy cq-independent public-record fixture, NOT a quantum attack test.
"""
import hashlib,itertools,json,collections
P=5
checks=0

def H(*args):
 h=hashlib.sha256()
 for x in args:
  x=json.dumps(x,sort_keys=True,separators=(',',':')).encode()
  h.update(len(x).to_bytes(4,'big'));h.update(x)
 return h.hexdigest()[:16]

def record(j,target_root,u,v,y,which):
 # A/B labels share t-u; A/C labels share t-v: all corrupt occurrences
 # are exposed, honest ciphertext groups have been replaced with ZERO.
 public_corrupt=((target_root-u)%P,(target_root-u)%P,
                 (target_root-v)%P,(target_root-v)%P)
 # 3 related capsules; all off-target source key witnesses, sharing tapes,
 # native signatures are known and may be revealed. None depends on root_j.
 others={k:{'root':(which+2*k)%P,
            'honest_source_secret':((k+3)*17, (k+3)*29),
            'sharing_tapes':((k+which)%P,(k+which+2)%P),
            'signature':H('native-signature',k,which),
            'encryption_coins':(k+7,which+11)}
        for k in range(3) if k!=j}
 ctx={'relation':'R106-restricted','claim':'UTXO:protected','branch':'challenge',
      'anchors':'BTC/SYS-window','native_vk':'vk-fixed','j':j}
 # PRG challenger y independent of t, full Dsig + CK/Aux recomputed.
 dsig=H('masked-sig',j,y,ctx)
 ciphertexts={k:('real-related-ciphertext',others[k]['root']) for k in others}
 ciphertexts[j]=('honest-zero-target','malicious-all-shares-public',public_corrupt)
 manifest=H('manifest',ciphertexts,dsig,ctx,others)
 ck=H('CK',y,manifest,dsig,ctx)
 aux=H('Aux',y,ck,manifest,ctx,others)
 pub=(j,public_corrupt,dsig,manifest,ck,aux,
      tuple(sorted((k,tuple(ciphertexts[k])) for k in ciphertexts)))
 return pub,others

def transcript(j,t,u,v,y,which,policy):
 pub,others=record(j,t,u,v,y,which)
 opts=sorted(others)
 # The adversary may examine the entire correlated public record before
 # choosing an off-target credential-witness opening; second opening may
 # depend adaptively on first opening contents. All off-target openings
 # expose the COMPLETE honest LWE source secret, share tapes and native sig.
 if policy==0: requests=[]
 elif policy==1: requests=[opts[0]]
 elif policy==2: requests=[opts[1]]
 elif policy==3:
  first=opts[int(pub[3],16)%2]
  requests=[first]
  if int(H(pub,others[first]),16)%2: requests.append(opts[1] if first==opts[0] else opts[0])
 elif policy==4: requests=opts
 disclosures=tuple((r,tuple(sorted(others[r].items()))) for r in requests)
 return (pub,disclosures)

def main():
 global checks
 result={}
 for j,which,policy in itertools.product(range(3),range(2),range(5)):
  views=[]
  for t in range(P):
   hist=collections.Counter(transcript(j,t,u,v,y,which,policy)
       for u,v,y in itertools.product(range(P),repeat=3))
   assert sum(hist.values())==P**3;checks+=1
   views.append(hist)
  assert all(h==views[0] for h in views); checks+=1
  assert all(v==1 for v in views[0].values());checks+=1
 result={'run':'R106-CAPSULE-LOCAL-LWE-SELECTIVE-OPENING-20261106',
       'status':'PASS', 'whole_joint_histogram_equalities':30,
       'censused_root_public_pairs':3*2*5*5*P**3,
       'assertions':checks,'adversarial_off_target_opening_policies':5,
       'complete_off_target_key_disclosures':True,
       'target_honest_ciphertexts':'zero, simulated under INDCPA',
       'target_PRG':'independently uniform, simulated under QPT PRG',
       'warning':'toy final-hybrid distribution equality, not primitive QPT security'}
 print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
