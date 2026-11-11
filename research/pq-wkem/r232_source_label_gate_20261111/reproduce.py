#!/usr/bin/env python3
"""Small R232 hash-label / same-message-signature reproduction, not WKEM."""
import hashlib, json

def H(*args):
    return hashlib.sha256(b''.join(len(x).to_bytes(2, 'big')+x for x in args)).digest()
def X(a,b): return bytes(x^y for x,y in zip(a,b))

def main():
    n=0
    def ck(q):
        nonlocal n
        assert q
        n+=1
    anchor=H(b'fixed source anchor')
    secret=H(b'frozen claim-scoped cancellation signature')
    # Public input labels are enough to choose mutually inconsistent
    # occurrences of z in an UNSAT predicate z AND NOT z.
    l0=H(b'public label',anchor,b'0')
    l1=H(b'public label',anchor,b'1')
    row11=X(secret,H(b'garbled AND-row 11',l1,l0))
    ck(all(not(z and (not z)) for z in (False, True)))
    ck(X(row11,H(b'garbled AND-row 11',l1,l0))==secret)
    for i in range(16):
        setup_digest=H(b'future work',bytes([i]),b'preselected')
        actual_digest=H(b'future work',bytes([i]),b'actual')
        ck(H(b'label',setup_digest)!=H(b'label',actual_digest))
        private_salt=H(b'private setup salt',bytes([i]))
        ck(H(b'label',private_salt)!=H(b'public label',anchor,bytes([i])))
    # Synthetic native verification accepts a Lamport signature with an
    # ignored trailing byte. Mutating that byte gives a new accepted
    # same-message signature: strong forgery, not an ordinary EUF new message.
    halves=[[H(b'half',bytes([i,b])) for b in (0,1)] for i in range(8)]
    vk=[[H(b'vk',x) for x in p] for p in halves]
    msg=83
    sig=b''.join(halves[i][(msg>>i)&1] for i in range(8))
    def verify(z):
        return len(z)==257 and all(H(b'vk',z[32*i:32*(i+1)])==vk[i][(msg>>i)&1] for i in range(8))
    sig0,sig1=sig+b'\0',sig+b'\1'
    ck(verify(sig0));ck(verify(sig1))
    ck(sig0!=sig1 and H(b'commit',sig0)!=H(b'commit',sig1))
    return {'checks':n,'status':'restricted local regressions; no ORIGINAL Build/Open',
            'unsolved':'source-dependent transfer of one private garbled input label from actual authenticated evidence'}

if __name__=='__main__':print(json.dumps(main(),sort_keys=True,indent=2))
