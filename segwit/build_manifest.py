"""Online PUBLIC-DATA builder for the companion signer. Never loads private keys.
Queries every address in an Electrum public_inventory.json against a fork
Esplora API, then verifies selected amounts/scripts using raw parent bytes.
"""
import argparse, concurrent.futures, datetime, json, os, pathlib, time, urllib.parse, urllib.request
import offline_sweep as signer
CHECKPOINT='0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb'

def collect(inventory, get, workers=4):
    if inventory.get('format')!='electrum-public-inventory/v1': raise ValueError('Wrong public inventory format')
    rows=inventory['addresses']
    if not rows or len({r['address'] for r in rows})!=len(rows): raise ValueError('Empty or duplicate address inventory')
    for r in rows:
        if signer.destination_script(r['address'],'bc').hex()!=r['script_pubkey'] or len(r['script_pubkey'])!=44:
            raise ValueError('Public address/script mismatch')
    if get('/block-height/961640')!=CHECKPOINT: raise ValueError('Endpoint does not report the expected BLAKE2b checkpoint')
    tip=get('/blocks/tip/hash'); block=get('/block/'+tip)
    if block['height']<961640: raise ValueError('Fork is below activation')
    def query(row):
        found=get('/address/'+row['address']+'/utxo')
        if not isinstance(found,list): raise ValueError('Unexpected UTXO response')
        return row,found
    selected=[]; excluded=[]; seen=set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for n,(row,found) in enumerate(pool.map(query,rows),1):
            for coin in found:
                status=coin['status']
                if not status['confirmed'] or status['block_height']>block['height']:
                    excluded.append(dict(address=row['address'],coin=coin,reason='Unconfirmed or newer than snapshot')); continue
                point=(coin['txid'],coin['vout'])
                if point in seen: raise ValueError('Duplicate outpoint from API')
                seen.add(point)
                selected.append(dict(txid=coin['txid'],vout=coin['vout'],value_sats=coin['value'],script_pubkey=row['script_pubkey'],creation_height=status['block_height']))
            if n%50==0 or n==len(rows): print(f'Checked {n}/{len(rows)} addresses; {len(selected)} candidates',flush=True)
    if not selected: raise ValueError('No confirmed outputs found in the supplied address range')
    txids=sorted({r['txid'] for r in selected})
    def parent(txid):
        raw=get('/tx/'+txid+'/hex')
        parsed=signer.parse_transaction(bytes.fromhex(raw))
        if parsed.txid!=txid: raise ValueError('Parent transaction hash mismatch')
        return txid,(raw,parsed)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool: parents=dict(pool.map(parent,txids))
    # Confirm these candidate outputs still appear unspent after the address scan.
    def outspends(txid):
        spends=get('/tx/'+txid+'/outspends')
        if not isinstance(spends,list) or len(spends)!=len(parents[txid][1].outputs):
            raise ValueError('Incomplete outspend response')
        return txid,spends
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool: spends=dict(pool.map(outspends,txids))
    kept=[]
    for r in selected:
        parsed=parents[r['txid']][1]
        if type(r['vout']) is not int or not 0<=r['vout']<len(parsed.outputs): raise ValueError('Invalid output index')
        value,script=parsed.outputs[r['vout']]
        if value!=r['value_sats'] or script.hex()!=r['script_pubkey']: raise ValueError('API amount/script disagrees with raw parent')
        if spends[r['txid']][r['vout']]['spent']:
            excluded.append(dict(coin=r,reason='Reported spent during final check')); continue
        entry={k:r[k] for k in ('txid','vout','value_sats','script_pubkey')}
        if parsed.coinbase:
            confirmations=block['height']-r['creation_height']+1
            if confirmations<101:
                excluded.append(dict(coin=r,reason='Below 101 coinbase confirmations')); continue
            entry['confirmations']=confirmations
        kept.append(entry)
    if get('/block-height/'+str(block['height']))!=tip: raise ValueError('Snapshot reorganized; rerun')
    if not kept: raise ValueError('No eligible unspent outputs remain')
    manifest=dict(format='offline-p2wpkh-sweep/v2',signing_profile=signer.PROFILE,snapshot=dict(height=block['height'],block_hash=tip),transactions={r['txid']:parents[r['txid']][0] for r in kept},utxos=kept)
    evidence=dict(checked_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),snapshot=manifest['snapshot'],addresses_checked=len(rows),included_outputs=len(kept),included_sats=sum(r['value_sats'] for r in kept),excluded=excluded,outspends=spends,note='Selected outputs were reported unspent after the snapshot. Explorer data is trusted; new receipts after the snapshot are excluded. Not full-node validation.')
    return manifest,evidence

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inventory',type=pathlib.Path,required=True)
    ap.add_argument('--out',type=pathlib.Path,required=True,help='NEW public output directory')
    ap.add_argument('--api',default='https://mempool.guide/api')
    ap.add_argument('--workers',type=int,default=4)
    args=ap.parse_args()
    if args.out.exists(): raise ValueError('Output directory exists')
    if not 1<=args.workers<=16: raise ValueError('Use 1 to 16 workers')
    url=urllib.parse.urlsplit(args.api)
    if url.scheme!='https' or not url.netloc or url.username or url.password: raise ValueError('Use an HTTPS API endpoint without credentials in its URL')
    inventory=json.loads(args.inventory.read_text(encoding='utf-8'))
    def get(path):
        for attempt in range(5):
            try:
                req=urllib.request.Request(args.api.rstrip('/')+path,headers={'User-Agent':'Public-Fork-Manifest/1.0','Cache-Control':'no-cache'})
                with urllib.request.urlopen(req,timeout=30) as response: text=response.read().decode()
                try: return json.loads(text)
                except json.JSONDecodeError: return text.strip()
            except Exception:
                if attempt==4: raise
                time.sleep(min(2**attempt,10))
    manifest,evidence=collect(inventory,get,args.workers)
    evidence['source']=args.api
    args.out.mkdir(mode=0o700)
    path=args.out/'manifest.json'
    path.write_text(json.dumps(manifest,indent=2)+'\n')
    signer.load_manifest(path)
    (args.out/'verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('Created manifest.json:',len(manifest['utxos']),'outputs;',evidence['included_sats'],'satoshis')
if __name__=='__main__': main()
