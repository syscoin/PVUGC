import hashlib,json,random
from collections import deque

def h(label,x): return hashlib.sha256(label + x).digest()
def token(ku, u, v): return h(b'edge/R389/v1\0',u.encode()+b'\0'+v.encode()+b'\0'+ku)
def xorb(a,b):return bytes(x^y for x,y in zip(a,b))

def graph_capsule(vertices,edges,s,t,seed):
  r=random.Random(seed)
  keys={v:r.getrandbits(256).to_bytes(32,'big') for v in vertices}
  ct={(u,v):xorb(keys[v],token(keys[u],u,v)) for u,v in edges}
  message=h(b'R389/msg', str(seed).encode())
  encrypted=xorb(message,h(b'R389/pad',keys[t]))
  return {'start_key':keys[s], 'ct':ct,'encrypted':encrypted},keys,message

def paths_reachable(caps,s,edges):
  known={s:caps['start_key']}
  q=deque([s]); edge_map={}
  for u,v in edges:edge_map.setdefault(u,[]).append(v)
  while q:
    u=q.popleft()
    for v in edge_map.get(u,[]):
      kv=xorb(caps['ct'][(u,v)],token(known[u],u,v))
      if v in known:
        assert known[v]==kv
      else:known[v]=kv;q.append(v)
  return known

def main():
  vertices=['s','a0','a1','b0','b1','t']
  # A forces x=0; B forces x=1. The globally consistent relation is FALSE.
  # In an occurrence-switchable graph, A's x=0 edge is followed by B's x=1 edge.
  naive=[('s','a0'),('a0','b1'),('b1','t')]
  consistent=[('s','a0'),('a0','b0'),('b1','t')]
  # End t unreachable under correct equality-preserving machine.
  details=[]
  for name,edges in [('naive_switching',naive),('consistent_memory',consistent)]:
    cap,keys,msg=graph_capsule(vertices,edges,'s','t',0xC0DE)
    known=paths_reachable(cap,'s',edges)
    present='t' in known
    if present:
      opened=xorb(cap['encrypted'],h(b'R389/pad',known['t']))
      assert opened==msg
    else:
      assert known.keys().isdisjoint({'t','b1'})
    details.append({'fixture':name,'reachable':present, 'learned_vertices':sorted(known),
      'legitimate_open':present, 'ciphertext_sha256':hashlib.sha256(cap['encrypted']).hexdigest()})
  assert details[0]['reachable'] and not details[1]['reachable']
  # Structural regression: adding all locally conceivable transitions to the
  # correct graph recreates the invalid public s-t path; labels cannot know
  # which edge was authenticated in the future without a cryptographic gate.
  wrong_edge=('a0','b1')
  assert wrong_edge not in consistent
  cap,keys,msg=graph_capsule(vertices,consistent+[wrong_edge],'s','t',0xC0DE)
  assert 't' in paths_reachable(cap,'s',consistent+[wrong_edge])
  print(json.dumps({'cases':details,'fabricated_public_edge_unlocks':True,
     'scope':'explicit public directed graph only; no original SHA/AuxPoW relation, no QPT proof'},sort_keys=True,indent=2))
if __name__=='__main__':main()
