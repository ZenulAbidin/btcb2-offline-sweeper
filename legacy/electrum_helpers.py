r"""Load locally in Electrum's console. No network calls or transactions.
exec(open(r'C:\offline\electrum_helpers.py', encoding='utf-8').read())
export_public_inventory(r'C:\offline\public_inventory.json', per_branch=2000)
# Later, after constructing and reviewing your own fork manifest:
export_manifest_keys(r'C:\offline\manifest.json', r'C:\offline\public_inventory.json', r'C:\offline\keys.txt')
"""
def export_public_inventory(output_path, per_branch=2000):
    import json, os
    from electrum import bitcoin
    if type(per_branch) is not int or not 1 <= per_branch <= 100000:
        raise ValueError('Choose an explicit address count from 1 to 100000 per branch')
    zpub=wallet.get_master_public_key()
    if not isinstance(zpub,str) or not zpub.startswith('xpub'):
        raise ValueError('This helper supports standard deterministic mainnet legacy P2PKH xpub wallets only')
    rows=[]
    for branch in (0,1):
        for index in range(per_branch):
            address=wallet.derive_address(branch,index)
            script=bitcoin.address_to_script(address)
            if isinstance(script,bytes): script=script.hex()
            if not isinstance(script,str) or len(script)!=50 or not script.startswith('76a914') or not script.endswith('88ac'):
                raise ValueError('Expected legacy P2PKH addresses')
            rows.append(dict(branch=branch,index=index,address=address,script_pubkey=script))
    result=dict(format='electrum-public-inventory/v1',zpub=zpub,per_branch=per_branch,addresses=rows)
    fd=os.open(output_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as output:
        json.dump(result,output,indent=2)
    print('Exported '+str(len(rows))+' public addresses. No private keys exported.')

def export_manifest_keys(manifest_path, inventory_path, output_path):
    import json, os
    from pathlib import Path
    from electrum import bitcoin
    manifest=json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    inventory=json.loads(Path(inventory_path).read_text(encoding='utf-8'))
    if inventory.get('format')!='electrum-public-inventory/v1':
        raise ValueError('Wrong public inventory format')
    if wallet.get_master_public_key()!=inventory['zpub'] or wallet.is_watching_only():
        raise ValueError('Open the matching software wallet with private-key access')
    if manifest.get('format')!='offline-p2pkh-sweep/v1' or manifest.get('signing_profile')!='knots-unified-p2pkh-compressed-0x21/v1':
        raise ValueError('Wrong signing manifest format or profile')
    wanted={u['script_pubkey'] for u in manifest['utxos']}
    if not wanted: raise ValueError('No inputs selected')
    selected={}
    for row in inventory['addresses']:
        if row['script_pubkey'] not in wanted: continue
        branch,index=row['branch'],row['index']
        if type(branch) is not int or branch not in (0,1) or type(index) is not int or not 0<=index<2**31:
            raise ValueError('Invalid public derivation suffix')
        address=wallet.derive_address(branch,index)
        derived_script=bitcoin.address_to_script(address)
        if isinstance(derived_script,bytes): derived_script=derived_script.hex()
        if address!=row['address'] or derived_script!=row['script_pubkey']:
            raise ValueError('Public inventory does not match this wallet')
        if row['script_pubkey'] in selected:
            raise ValueError('Duplicate public inventory entry')
        selected[row['script_pubkey']]=row
    if set(selected)!=wanted:
        raise ValueError('Manifest includes an address outside this public inventory; extend the inventory')
    if Path(output_path).exists(): raise ValueError('Output file exists; choose a new filename')
    password=None; keys=[]; key=None
    try:
        if wallet.has_password():
            password=window.password_dialog('Wallet password for local export of the selected input keys')
            if password is None:
                print('Cancelled'); return
        for row in selected.values():
            key=wallet.export_private_key_for_path([row['branch'],row['index']],password)
            if not key.startswith('p2pkh:') or bitcoin.address_from_private_key(key)!=row['address']:
                raise ValueError('Private-key/address verification failed')
            keys.append(key.split(':',1)[1])
        fd=os.open(output_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='ascii',newline='\n') as output:
            output.write('\n'.join(keys)+'\n')
        print('Saved '+str(len(keys))+' unique input keys locally. Keep this file offline.')
    finally:
        password=None; key=None; keys.clear()
