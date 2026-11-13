#!/usr/bin/env python3
"""Toy SHA256d parent-work diversity, source-derived release attempts.

NOT a Bitcoin/Syscoin verifier, WKEM, full source relation or QPT test.
Parent SHA256d work only, synthetic coinbase Merkle roots and source heights.
"""
import hashlib, json, struct
from collections import Counter

C=Counter()
def check(cond, label):
    if not cond: raise AssertionError(label)
    C[label]+=1

def H(*parts):
    return hashlib.sha256(b''.join(len(p).to_bytes(4,'big')+p for p in parts)).digest()

def sha2(b):return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))

ANCHOR=H(b'btc-anchor',b'fixed-parent-prev')
CHILD_A=H(b'syscoin-child',b'branch-A')
CHILD_B=H(b'syscoin-child',b'branch-B')
ANC_A=H(b'syscoin-ancestor',b'branch-A')
ANC_B=H(b'syscoin-ancestor',b'branch-B')
TARGET=1<<(256-9)

def header(nonce,child,ancestor,prev=ANCHOR):
    # Synthetic output explicitly NOT the source's actual AuxPoW serialization.
    synthetic_coinbase=b'SYS-tag:'+ancestor+struct.pack('<I',120)+b'child:'+child
    root=sha2(synthetic_coinbase)
    return struct.pack('<I',4)+prev+root+struct.pack('<I',1700000000)+struct.pack('<I',0x1e00ffff)+struct.pack('<I',nonce)

def valid(h):
    return len(h)==80 and h[4:36]==ANCHOR and int.from_bytes(sha2(h),'big')<TARGET

def mine(child,ancestor,count=12):
    out=[]; nonce=0
    while len(out)<count:
        h=header(nonce,child,ancestor)
        if valid(h):out.append((nonce,h,sha2(h)))
        nonce+=1
    return out

def main():
    a=mine(CHILD_A,ANC_A)
    b=mine(CHILD_B,ANC_B)
    check(len(a)==12 and len(b)==12,'mined_count')
    check(len(set(d for _,_,d in a+b))==24,'all_parent_hashes_distinct')
    check(all(valid(h) for _,h,d in a+b),'synthetic_parent_pow')
    check(all(d[0]==0 for _,h,d in a+b),'eight_common_zero_hash_bits')
    check(all(int.from_bytes(d,'big')<TARGET for _,h,d in a+b),'ninth_bit_target_bound')

    # Model realistic source roles: distinct forks require separate parent-work
    # commitments; no collision is implied by different ancestor tags.
    check(CHILD_A!=CHILD_B and ANC_A!=ANC_B,'distinct_semantic_children')
    check(len(set(d for _,_,d in a).intersection(set(d for _,_,d in b)))==0,
          'incompatible_parents_do_not_collide')
    check(a[0][1][4:36]==b[0][1][4:36]==ANCHOR,
          'common_bitcoin_predecessor')
    check(not valid(header(a[0][0],CHILD_A,ANC_A,prev=H(b'other-anchor'))),
          'unanchored_parent_rejected')

    context=H(b'vault',b'claim',b'cancel-path')
    signature=H(b'frozen-native-signature-stand-in',context)
    # candidate 1: stable anchor key is common but public before source event
    stable=H(b'key/from-anchor',context,ANCHOR)
    sealed=xor(signature,H(b'pad',stable))
    opened=xor(sealed,H(b'pad',H(b'key/from-anchor',context,ANCHOR)))
    check(opened==signature,'public_anchor_opens_early')

    # candidate 2: hash of the actual valid work transcript is hidden until
    # found, but differs with nonce and fork: no common precommitted key.
    derived=[H(b'key/from-parent',context,h) for _,h,d in a+b]
    check(len(set(derived))==24,'work_specific_keys_differ')
    key1=derived[0]
    sealed1=xor(signature,H(b'pad',key1))
    for k in derived[1:]:
        check(xor(sealed1,H(b'pad',k))!=signature,
              'different_original_witness_cannot_open_same_key')

    # candidate 3: shared PoW prefix is a public, attacker-chosen constant,
    # even without SHA header preimage / parent anchor.
    prefix_key=H(b'key/from-prefix',context,b'\x00')
    sealed_prefix=xor(signature,H(b'pad',prefix_key))
    check(all(d[0]==0 and H(b'key/from-prefix',context,d[:1])==prefix_key
              for _,h,d in a+b),'common_prefix_for_all_valid_work')
    fabricated_digest=b'\x00'+b'\xff'*31  # no valid authenticated parent header
    check(xor(sealed_prefix,H(b'pad',H(b'key/from-prefix',context,
             fabricated_digest[:1])))==signature,'fabricated_digest_opens_prefix')

    # Null repair: if a custom encrypted table publicly enumerates candidates,
    # attackers who know any enumerated candidate need no authenticated Bitcoin
    # best-chain inclusion. Here an actual locally-mined header is not best-chain.
    published_table={H(b'index',h).hex():sealed1.hex() for _,h,_ in a}
    check(H(b'index',a[0][1]).hex() in published_table,
          'enumerated_local_work_lookup')
    check(len(published_table)==12,'enumeration_table_not_universal')
    check(H(b'index',b[0][1]).hex() not in published_table,
          'enumeration_misses_other_valid_fork')

    result={'run':'R192_SOURCEHASH_SHA_OR',
      'scope':'Synthetic SHA256d parent-work diversity and direct release attempts only',
      'assertions':sum(C.values()),'groups':dict(sorted(C.items())),
      'mined_A_first_nonce':a[0][0],'mined_B_first_nonce':b[0][0],
      'distinct_pow_solutions':len(a+b),
      'sample_sha256d_parent_A':a[0][2].hex(),
      'sample_sha256d_parent_B':b[0][2].hex(),
      'not_implemented':['real Bitcoin DAA/best-chain',
         'Syscoin AuxPoW/coinbase tag consensus validation','PoB burn proofs',
         'original-witness-conditioned key release',
         'native signatures','QPT security'],
      'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}
    return result

if __name__=='__main__':print(json.dumps(main(),indent=2,sort_keys=True))
