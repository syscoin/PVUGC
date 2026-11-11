#!/usr/bin/env python3
"""R222: public path-potential release tests. Algebra/synthetic hash paths only.
NOT an ORIGINAL witness-KEM and NOT a Bitcoin/Syscoin authenticity test.
"""
import hashlib, json, secrets

def H(domain,*vals):
    s=domain.encode()+b'\0'
    for v in vals:s+=len(v).to_bytes(4,'big')+v
    return hashlib.sha256(s).digest()

def xor(a,b):
    assert len(a)==len(b)
    return bytes(x^y for x,y in zip(a,b))

def path_edges(xs):
    return list(zip(xs[:-1],xs[1:]))

def public_p(v):return H('R222/publicpotential',v)

def dp_public(u,v):return xor(public_p(u),public_p(v))

def release_via_path(C, xs):
    delta=bytes(32)
    for u,v in path_edges(xs):delta=xor(delta,dp_public(u,v))
    return xor(C['wrapped_root'],xor(delta,public_p(xs[-1])))

def secret_p(seed,v):return H('R222/privatepotential',seed,v)

def private_edges(seed,xs):return [xor(secret_p(seed,u),secret_p(seed,v)) for u,v in path_edges(xs)]

def release_secret_path(C, xs, edges, terminal):
    t=bytes(32)
    for e in edges:t=xor(t,e)
    return xor(C['wrapped_root'],xor(t,terminal))

def main():
    counts={'public_potential_releases_all_authenticated_paths':0,
            'fabricated_path_releases_without_source_authentication':0,
            'public_root_releases_directly':0,
            'secret_label_missing_on_future_edges':0,
            'secret_seed_retention_releases_early':0,
            'independent_future_path_does_not_supply_secret_endpoint':0,
            'different_paths_same_key':0}
    for i in range(64):
        q=H('seed',i.to_bytes(4,'big'))
        root=H('root',q)
        true1=[root,H('genuine-child-1',q),H('genuine-child-2',q)]
        true2=[root,H('genuine-child-3',q),H('genuine-child-4',q)]
        bogus=[root,H('fake-without-work',q),H('fake-descendant',q)]
        K=H('frozen-K',q)
        C={'wrapped_root':xor(K,public_p(root))}
        for path in (true1,true2):
            assert release_via_path(C,path)==K
            counts['public_potential_releases_all_authenticated_paths']+=1
        assert release_via_path(C,true1)==release_via_path(C,true2)
        counts['different_paths_same_key']+=1
        assert release_via_path(C,bogus)==K
        counts['fabricated_path_releases_without_source_authentication']+=1
        assert xor(C['wrapped_root'],public_p(root))==K
        counts['public_root_releases_directly']+=1
        # Repair: make potentials depend on a truly hidden independent setup seed.
        seed=H('private-seed',q)
        private_C={'wrapped_root':xor(K,secret_p(seed,root))}
        # The builder can compute only prior/known edges; the future witness
        # contains header hashes/coinbase and SHA siblings, not secret labels.
        known_edges=private_edges(seed,true1)
        assert len(known_edges)==2 and all(len(e)==32 for e in known_edges)
        fresh_edges=private_edges(seed,true2)
        assert known_edges!=fresh_edges
        counts['secret_label_missing_on_future_edges']+=1
        # Malicious setup retaining its seed breaks secrecy immediately.
        assert xor(private_C['wrapped_root'],secret_p(seed,root))==K
        counts['secret_seed_retention_releases_early']+=1
        # A public source transcript (node IDs) alone lacks the secret terminal
        # potential; supplying all secret labels restores completeness only by
        # adding a non-source-specific oracle/source authority.
        assert len(true2)==3 and all(len(x)==32 for x in true2)
        assert release_secret_path(private_C,true2,fresh_edges,secret_p(seed,true2[-1]))==K
        counts['independent_future_path_does_not_supply_secret_endpoint']+=1
    return {'run':'R222-EPR-20261111','status':'failed candidate, not a WKEM',
            'tests':counts,'checks':sum(counts.values()),
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}
if __name__=='__main__': print(json.dumps(main(),indent=2,sort_keys=True))
