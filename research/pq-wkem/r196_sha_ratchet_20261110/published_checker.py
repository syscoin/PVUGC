#!/usr/bin/env python3
"""R196 SHA witness-ratchet functional regression, not secure source release."""
import hashlib, json

def H(*xs):
    return hashlib.sha256(b''.join(len(x).to_bytes(4,'big')+x for x in xs)).digest()
def X(a,b): return bytes(x^y for x,y in zip(a,b))
def child(s,tag): return H(b'child',s,tag)
def state(trace):
    s=H(b'fixed public anchor')
    for c in trace: s=H(b'ratchet',s,c)
    return s

def run():
    counts={k:0 for k in ('fork_fails_common_signature','prefix_leaks_early',
                          'explicit_rows_only_list_known_forks','universal_row_leaks_on_fake')}
    for i in range(32):
        seed=i.to_bytes(4,'little')
        prefix=[child(seed,b'common'+bytes([j])) for j in range(4)]
        a=prefix+[child(seed,b'A')]
        b=prefix+[child(seed,b'B')]
        c=prefix+[child(seed,b'C')]
        k=H(b'cancel',seed)
        pad=lambda s:H(b'pad',s)
        e=X(k,pad(state(a)))
        assert X(e,pad(state(a)))==k
        assert X(e,pad(state(b)))!=k
        counts['fork_fails_common_signature']+=1
        e0=X(k,pad(state(prefix)))
        assert X(e0,pad(state(prefix)))==k
        counts['prefix_leaks_early']+=1
        rows={state(t):X(k,pad(state(t))) for t in (a,b)}
        assert all(X(rows[state(t)],pad(state(t)))==k for t in (a,b))
        assert state(c) not in rows
        counts['explicit_rows_only_list_known_forks']+=1
        fake=state(prefix+[child(seed,b'forged')])
        universal=lambda s:X(k,pad(s))
        assert X(universal(fake),pad(fake))==k
        counts['universal_row_leaks_on_fake']+=1
    return {'run':'R196','counts':counts,'assertions':sum(counts.values()),
            'scope':'synthetic SHA functional checks only, no source authentication or WE'}
if __name__=='__main__': print(json.dumps(run(),indent=2,sort_keys=True))
