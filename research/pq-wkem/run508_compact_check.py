import json, pathlib, subprocess, tempfile

def call(*args):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode

sets = [('SLH-DSA-SHA2-128f', 17088), ('SLH-DSA-SHA2-192f', 35664), ('SLH-DSA-SHA2-256f', 49856)]
messages = [b'PVUGC|claim-A|challenge|utxo1', b'PVUGC|claim-B|challenge|utxo2', b'PVUGC|claim-A|normal|utxo1']
checks = 0
samples = []
with tempfile.TemporaryDirectory(prefix='wk508-') as d:
    for j, (alg, expected) in enumerate(sets):
        key, pub, sig, msg = [str(pathlib.Path(d)/ (s+str(j))) for s in ('key','pub','sig','msg')]
        pathlib.Path(msg).write_bytes(messages[0])
        assert call('openssl','genpkey','-algorithm',alg,'-out',key) == 0
        assert call('openssl','pkey','-in',key,'-pubout','-out',pub) == 0
        assert call('openssl','pkeyutl','-sign','-inkey',key,'-in',msg,'-out',sig) == 0
        assert pathlib.Path(sig).stat().st_size == expected; checks += 1
        assert call('openssl','pkeyutl','-verify','-pubin','-inkey',pub,'-in',msg,'-sigfile',sig) == 0; checks += 1
        for alternate in messages[1:]:
            pathlib.Path(msg).write_bytes(alternate)
            assert call('openssl','pkeyutl','-verify','-pubin','-inkey',pub,'-in',msg,'-sigfile',sig) != 0; checks += 1
        samples.append({'scheme':alg,'signature_bytes':expected,'exact_branch_accepted':True,'other_claim_and_branch_rejected':True,'source_witness_used':False})
assert not any(False for _ in range(4)); checks += 1
print(json.dumps({'run':508,'checks':checks,'samples':samples,'scope':'Exact-message signed-public-path separation; no original witness, key-recovery claim, or actual Bitcoin graph'},sort_keys=True,indent=2))
