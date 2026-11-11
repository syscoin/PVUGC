#!/usr/bin/env python3
"""R231: source entropy/pad and table-cover counterchecks. NOT WKEM or BTC/SYS verification."""
import hashlib, itertools, json
from collections import Counter

checks=Counter()
def ck(cond,name):
    assert cond, name
    checks[name]+=1

def h(domain,*inputs):
    x=domain.encode()+b'\0'
    for b in inputs: x+=len(b).to_bytes(4,'big')+b
    return hashlib.sha256(x).digest()

# Exact one-time-pad posterior: K,C,S,W are 4-bit. C=K xor S,
# W sampled independently AFTER setup. Conditioning on C,W leaves K uniform.
nbits=4;size=1<<nbits
for c,w in itertools.product(range(size),repeat=2):
    compatible=[]
    for k,s in itertools.product(range(size),repeat=2):
        if (k^s)==c:
            compatible.append(k)
    ck(len(compatible)==size,'posterior_size')
    for k in range(size):
        ck(compatible.count(k)==1,'posterior_uniform')

# Real SHA256 domain separation, but deliberately not a real PoW source.
values=[i.to_bytes(2,'big') for i in range(256)]
pads=[h('source-pad',v) for v in values]
setup_pad=pads[0];native_signature=h('synthetic-frozen-native-signature',b'claim-W')
D=bytes(a^b for a,b in zip(native_signature,setup_pad))
ck(bytes(a^b for a,b in zip(D,pads[0]))==native_signature,'guessed_source_correct')
wrong=sum(bytes(a^b for a,b in zip(D,p))!=native_signature for p in pads[1:])
ck(wrong==255,'alternate_source_wrong_native_output')

# Prefix constrained by a toy work target is public from target itself.
work_prefix=bytes([0])
public_prefix_pad=h('work-prefix',work_prefix)
Dpub=bytes(a^b for a,b in zip(native_signature,public_prefix_pad))
ck(bytes(a^b for a,b in zip(Dpub,h('work-prefix',b'\0')))==native_signature,
   'target_invariant_public_decryption')

# A Merkle root is a public invariant even when authenticated membership paths
# differ; normalizing through the root does not supply a concealed pad.
leaves=[h('leaf',bytes([j])) for j in range(4)]
left=h('node',leaves[0],leaves[1]);right=h('node',leaves[2],leaves[3]);root=h('node',left,right)
assert h('node',h('node',leaves[0],leaves[1]),right)==root
assert h('node',left,h('node',leaves[2],leaves[3]))==root
Droot=bytes(a^b for a,b in zip(native_signature,h('merkle-root-pad',root)))
ck(bytes(a^b for a,b in zip(Droot,h('merkle-root-pad',root)))==native_signature,
   'public_merkle_root_decrypts_without_path')

# Preselected q future source labels: exact finite cover ratio q / 2^16;
# exposing their plaintexts to allow public Open lets anyone directly open.
future_universe=65536
for q in (1,2,8,32,256):
    secret_source_labels=list(range(q))
    cover=sum(w in secret_source_labels for w in range(future_universe))
    ck(cover==q,'bounded_table_cover')
    release_rows=[bytes(a^b for a,b in zip(native_signature,h('table-pad',w.to_bytes(2,'big'))))
                  for w in secret_source_labels]
    for w,row in zip(secret_source_labels,release_rows):
        out=bytes(a^b for a,b in zip(row,h('table-pad',w.to_bytes(2,'big'))))
        ck(out==native_signature,'published_table_leaks_without_source_membership')

# A setup-secret keyed hash works only if Open obtains the setup secret;
# publishing that secret makes the fixed public-label pad available early.
seed=h('private-setup-seed',b'isolated')
fixed_anchor=h('fixed-public-anchor',b'claim-W')
Dpriv=bytes(a^b for a,b in zip(native_signature,h('keyed',seed,fixed_anchor)))
ck(bytes(a^b for a,b in zip(Dpriv,h('keyed',seed,fixed_anchor)))==native_signature,
   'publishing_keyed_seed_opens_early')
ck(h('commit',seed)!=seed,'commitment_not_literal_seed')

result={'run':'R231_future_source_entropy_20261111',
        'assertions':sum(checks.values()),'groups':dict(sorted(checks.items())),
        'exact_otp_size':size,'future_universe':future_universe,
        'sha256_candidate_sources':len(values),
        'non_guessed_source_mismatches':wrong,
        'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
        'limits':['local illustrative SHA256 source bytes only',
                  'no Bitcoin/Syscoin work, chain or DA authentication',
                  'no Build/Open witness encryption', 'no QPT security claim',
                  'finite-table coverage models uniform independent source values only']}
print(json.dumps(result,indent=2,sort_keys=True))
