"""Online PUBLIC-DATA builder for the companion signer. Never loads private keys.
Queries every address in an Electrum public_inventory.json against a fork
Esplora API, then verifies selected amounts/scripts using raw parent bytes.
"""
import argparse, concurrent.futures, datetime, json, os, pathlib, time, urllib.parse, urllib.request
from collections import deque
import threading
try:
    from . import offline_sweep as signer
except ImportError:  # Preserve the original standalone command-line entrypoint.
    import offline_sweep as signer
CHECKPOINT='0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb'
MAX_ADDRESSES=200_000
MAX_SCAN_COINS=100_000
MAX_PARENT_HEX_CHARS=32*1024*1024
MAX_PARENT_OUTPUTS=200_000
MAX_JSON_BYTES=64*1024*1024
MAX_RESPONSE_BYTES=8*1024*1024


def bounded_map(function, items, workers):
    """Preserve input order with at most workers submitted futures at a time."""
    if type(workers) is not int or not 1<=workers<=16: raise ValueError('Use 1 to 16 workers')
    source=iter(items); pending=deque()
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        for _ in range(workers):
            try: item=next(source)
            except StopIteration: break
            pending.append(pool.submit(function,item))
        while pending:
            # Do not submit more work until the caller consumes this result.
            yield pending.popleft().result()
            try: item=next(source)
            except StopIteration: continue
            pending.append(pool.submit(function,item))
    finally:
        for future in pending: future.cancel()
        pool.shutdown(wait=True,cancel_futures=True)


def bounded_json(data):
    """Check the eventual saved size without making a second full JSON copy."""
    size=1
    for chunk in json.JSONEncoder(indent=2,allow_nan=False).iterencode(data):
        size+=len(chunk.encode('utf-8'))
        if size>MAX_JSON_BYTES: raise ValueError('Public result exceeds the 64 MiB safety limit; use a smaller inventory')


def public_coin(coin):
    """Discard unsupported API fields before retaining exclusion evidence."""
    if not isinstance(coin,dict) or not isinstance(coin.get('status'),dict):
        raise ValueError('Unexpected UTXO record')
    txid=signer.hex_bytes(coin.get('txid'),'API transaction ID',32).hex()
    vout=signer.strict_int(coin.get('vout'),'API output index',0,0xffffffff)
    value=signer.strict_int(coin.get('value'),'API output amount',0,signer.MAX_MONEY)
    status=coin['status']
    if type(status.get('confirmed')) is not bool: raise ValueError('Invalid confirmation status')
    clean_status={'confirmed':status['confirmed']}
    if status['confirmed']:
        clean_status['block_height']=signer.strict_int(status.get('block_height'),'creation height',0,0x7fffffff)
    return dict(txid=txid,vout=vout,value=value,status=clean_status)

def collect(inventory, get, workers=4, progress=None):
    if inventory.get('format')!='electrum-public-inventory/v1': raise ValueError('Wrong public inventory format')
    rows=inventory['addresses']
    if not isinstance(rows,list) or not 1<=len(rows)<=MAX_ADDRESSES: raise ValueError('Empty or oversized address inventory')
    if len({r['address'] for r in rows})!=len(rows): raise ValueError('Duplicate address inventory')
    if type(workers) is not int or not 1<=workers<=16: raise ValueError('Use 1 to 16 workers')
    budget={'scan_coins':0,'parent_hex':0,'parent_outputs':0}; budget_lock=threading.Lock()
    for r in rows:
        if signer.destination_script(r['address'],'bc').hex()!=r['script_pubkey'] or len(r['script_pubkey'])!=50:
            raise ValueError('Public address/script mismatch')
    if get('/block-height/961640')!=CHECKPOINT: raise ValueError('Endpoint does not report the expected BLAKE2b checkpoint')
    tip=signer.hex_bytes(get('/blocks/tip/hash'),'snapshot hash',32).hex(); block=get('/block/'+tip)
    if not isinstance(block,dict): raise ValueError('Invalid snapshot block')
    signer.strict_int(block.get('height'),'snapshot height',961640,0x7fffffff)
    def query(row):
        found=get('/address/'+row['address']+'/utxo')
        if not isinstance(found,list): raise ValueError('Unexpected UTXO response')
        with budget_lock:
            budget['scan_coins']+=len(found)
            if budget['scan_coins']>MAX_SCAN_COINS: raise ValueError('Too many explorer outputs; use a smaller inventory')
        return row,[public_coin(coin) for coin in found]
    selected=[]; excluded=[]; seen=set()
    results=bounded_map(query,rows,workers)
    try:
        for n,(row,found) in enumerate(results,1):
            for coin in found:
                status=coin['status']
                if not status['confirmed'] or status['block_height']>block['height']:
                    excluded.append(dict(address=row['address'],coin=coin,reason='Unconfirmed or newer than snapshot')); continue
                point=(coin['txid'],coin['vout'])
                if point in seen: raise ValueError('Duplicate outpoint from API')
                seen.add(point)
                selected.append(dict(txid=coin['txid'],vout=coin['vout'],value_sats=coin['value'],script_pubkey=row['script_pubkey'],creation_height=status['block_height']))
            if n%50==0 or n==len(rows):
                message=f'Checked {n}/{len(rows)} addresses; {len(selected)} candidates'
                if progress is not None: progress(message)
                else: print(message,flush=True)
    finally:
        results.close()
    if not selected: raise ValueError('No confirmed outputs found in the supplied address range')
    txids=sorted({r['txid'] for r in selected})
    def parent(txid):
        raw=get('/tx/'+txid+'/hex')
        if not isinstance(raw,str) or len(raw)>signer.MAX_PARENT_BYTES*2: raise ValueError('Invalid or oversized parent transaction')
        with budget_lock:
            budget['parent_hex']+=len(raw)
            if budget['parent_hex']>MAX_PARENT_HEX_CHARS: raise ValueError('Parent data exceeds the aggregate safety limit; use a smaller inventory')
        parsed=signer.parse_transaction(bytes.fromhex(raw))
        if parsed.txid!=txid: raise ValueError('Parent transaction hash mismatch')
        with budget_lock:
            budget['parent_outputs']+=len(parsed.outputs)
            if budget['parent_outputs']>MAX_PARENT_OUTPUTS: raise ValueError('Parent output count exceeds the aggregate safety limit')
        return txid,(raw,parsed)
    parents=dict(bounded_map(parent,txids,workers))
    # Confirm these candidate outputs still appear unspent after the address scan.
    def outspends(txid):
        spends=get('/tx/'+txid+'/outspends')
        if not isinstance(spends,list) or len(spends)!=len(parents[txid][1].outputs):
            raise ValueError('Incomplete outspend response')
        if any(not isinstance(row,dict) or type(row.get('spent')) is not bool for row in spends):
            raise ValueError('Invalid outspend state')
        return txid,[{'spent':row['spent']} for row in spends]
    spends=dict(bounded_map(outspends,txids,workers))
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
    manifest=dict(format='offline-p2pkh-sweep/v1',signing_profile=signer.PROFILE,snapshot=dict(height=block['height'],block_hash=tip),transactions={r['txid']:parents[r['txid']][0] for r in kept},utxos=kept)
    evidence=dict(checked_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),snapshot=manifest['snapshot'],addresses_checked=len(rows),included_outputs=len(kept),included_sats=sum(r['value_sats'] for r in kept),excluded=excluded,outspends=spends,note='Selected outputs were reported unspent after the snapshot. Explorer data is trusted; new receipts after the snapshot are excluded. Not full-node validation.')
    bounded_json(manifest); bounded_json(evidence)
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
    with args.inventory.open('rb') as handle: inventory_raw=handle.read(MAX_JSON_BYTES+1)
    if len(inventory_raw)>MAX_JSON_BYTES: raise ValueError('Inventory exceeds the 64 MiB safety limit')
    inventory=json.loads(inventory_raw,object_pairs_hook=signer.unique_json)
    def get(path):
        for attempt in range(5):
            try:
                req=urllib.request.Request(args.api.rstrip('/')+path,headers={'User-Agent':'Public-Fork-Manifest/1.0','Cache-Control':'no-cache'})
                with urllib.request.urlopen(req,timeout=30) as response: raw=response.read(MAX_RESPONSE_BYTES+1)
                if len(raw)>MAX_RESPONSE_BYTES: raise ValueError('Explorer response exceeds the 8 MiB safety limit')
                text=raw.decode()
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
