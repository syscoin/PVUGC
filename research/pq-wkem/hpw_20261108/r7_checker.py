"""HPW synthetic source-qualified PoW prefix-release regression.
No Bitcoin/Syscoin consensus implementation; standard library only.
"""
import hashlib, json, random, struct, statistics, itertools

def h(b):return hashlib.sha256(b).digest()
def h2(b):return h(h(b))
def check_key(ctx,k):return h(b'HPW/check\x00'+ctx+k)
def stream(ctx,k,length):
    blocks=[]
    for j in range((length+31)//32):blocks.append(h(b'HPW/mask\x00'+ctx+k+struct.pack('>I',j)))
    return b''.join(blocks)[:length]
def xor(a,b):return bytes(x^y for x,y in zip(a,b))

def frame(ctx, caproot, evidence, nonce):
    assert len(ctx)==32 and len(caproot)==32
    # Synthetic 80-byte parent header; changing nonce is an actual SHA256d work search.
    merkle=h2(b'HPW/coinbase/v1\x00'+caproot+ctx+evidence)
    prev=h2(b'HPW/prev-parent\x00'+evidence)
    return struct.pack('<I',2)+prev+merkle+struct.pack('<I',1720000000)+struct.pack('<I',0x207fffff)+struct.pack('<I',nonce)

def digestbits(digest,hbits,dbits):
    val=int.from_bytes(digest,'big')
    leading=val>>(256-hbits)
    token=(val>>(256-hbits-dbits))&((1<<dbits)-1)
    return leading,token

def mine(ctx,root,evidence,ck,dbits,hbits):
    # Attacker does not know k. It checks the public commitment of candidate token.
    # On fake evidence this still works identically.
    for nonce in range(1<<30):
        v=h2(frame(ctx,root,evidence,nonce)); a,b=digestbits(v,hbits,dbits)
        if a==0 and check_key(ctx,b.to_bytes((dbits+7)//8,'big'))==ck:
            return nonce,b,nonce+1,v.hex()
    raise RuntimeError('not found')

def original_source_valid(context, evidence):
    # Deliberately only a toy predicate. Actual SYS/BTC relation MUCH stronger.
    return evidence==b'anchor:authenticated-slot-5000|child:actual-fork|claim:real'

def run():
    rng=random.Random(0x48455708)
    hbits,dbits=4,9
    ctx=h(b'SYS/claim/bound-UTXO/path/anchor/window')
    root=h(b'capsule-table-root/baselines/ctx/pre-funding')
    genuine=b'anchor:authenticated-slot-5000|child:actual-fork|claim:real'
    fake=b'anchor:unrelated-slot-9999|child:arbitrary-bytes|claim:fake'
    assert original_source_valid(ctx,genuine)
    assert not original_source_valid(ctx,fake)
    attempts={'genuine':[],'fake':[]}
    checks=0
    direct_search_recoveries=0
    for case in range(16):
        token=rng.randrange(1<<dbits)
        k=token.to_bytes((dbits+7)//8,'big')
        ck=check_key(ctx,k)
        sigma=h(b'native-frozen-signature-fixture'+struct.pack('>I',case))*3
        D=xor(sigma,stream(ctx,k,len(sigma)))
        # The public check tag itself permits an offline exhaustive key search.
        brute=[v for v in range(1<<dbits) if check_key(ctx,v.to_bytes((dbits+7)//8,'big'))==ck]
        assert brute==[token]
        checks+=1
        guessed=brute[0].to_bytes((dbits+7)//8,'big')
        assert xor(D,stream(ctx,guessed,len(D)))==sigma
        checks+=1
        direct_search_recoveries+=1
        for label,w in [('genuine',genuine),('fake',fake)]:
            nonce,guess,count,raw=mine(ctx,root,w,ck,dbits,hbits)
            recovered=guess.to_bytes((dbits+7)//8,'big')
            assert guess==token
            checks+=1
            assert xor(D,stream(ctx,recovered,len(D)))==sigma
            checks+=1
            assert digestbits(bytes.fromhex(raw),hbits,dbits)==(0,token)
            checks+=1
            assert len(frame(ctx,root,w,nonce))==80
            checks+=1
            attempts[label].append(count)
    # Exact finite-field full-rank source-token independence, not a QPT test.
    q=7; xs=[1,2,3]; t=3
    all_eval={tuple(sum(c[j]*pow(x,j,q) for j in range(t))%q for x in xs)
              for c in itertools.product(range(q),repeat=t)}
    assert len(all_eval)==q**t  # each triple occurs once under a random polynomial
    checks+=1
    fcoef=[3,5,2]; masks=[6,4,1]
    target=tuple((masks[i]+sum(fcoef[j]*pow(x,j,q) for j in range(t)))%q
                 for i,x in enumerate(xs))
    matches=sum(tuple(z)==target for z in itertools.product(range(q),repeat=t))
    assert matches==1
    checks+=1
    independence={'field_size':q,'threshold':t,'distinct_row_vectors':len(all_eval),
                  'possible_public_source_token_tuples':q**t,'matching_tuples':matches,
                  'exact_independent_source_match_probability':f'1/{q**t}',
                  'interpretation':'Independent future PoW hashes do not become correlated hidden table tokens'}
    # The random-oracle law is independent of ORIGINAL source validity.
    p=2**(-(hbits+dbits))
    assert p==1/8192
    checks+=1
    return {'run':'HPW_R7_POW_PREFIX_SOURCE','toy':{'pow_zero_bits':hbits,'hidden_token_bits':dbits,'per_hash_success_probability':p,'theoretical_mean_attempts':2**(hbits+dbits)},'source_predicate':{'genuine':True,'fake':False},'mining':{k:{'trials':len(v),'total_hashes':sum(v),'mean_attempts':sum(v)/len(v),'min':min(v),'max':max(v)} for k,v in attempts.items()},'source_token_independence':independence,'direct_offline_key_search_recoveries':direct_search_recoveries,'unauthorized_fake_capability_recoveries':16,'genuine_capability_recoveries':16,'assertions':checks,'scope':'Toy SHA256d 80-byte parent headers; not real Syscoin consensus nor QPT security. Public tag target leaks equally from invalid source strings.'}

if __name__=='__main__':print(json.dumps(run(),indent=2,sort_keys=True))
