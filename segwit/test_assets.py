"""Only fixed PUBLIC test scalars and fictional outputs. Never fund test keys."""
import contextlib, io, json, pathlib, struct, sys, tempfile, types, unittest
from fractions import Fraction
from cryptography.exceptions import InvalidSignature
import offline_sweep as s
import build_manifest as builder
import electrum_helpers as helpers
import test_cli as cli
import test_offline_sweep as ref

class AssetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.folder=pathlib.Path(self.tmp.name)
        self.scripts=[cli.key_script(i) for i in (1,2,3)]
        self.addresses=[cli.address(script) for script in self.scripts]
        vin=b'\x55'*32+struct.pack('<I',0)+b'\x00'+b'\xff'*4
        self.raw=struct.pack('<I',2)+b'\x01'+vin+b'\x03'+b''.join(s.serialize_output(100000,script) for script in self.scripts)+b'\x00'*4
        self.txid=s.sha256d(self.raw)[::-1].hex()
        self.tip='66'*32
        self.inventory=dict(format='electrum-public-inventory/v1',zpub='zpub-public-test-only',addresses=[dict(branch=0,index=i,address=a,script_pubkey=self.scripts[i].hex()) for i,a in enumerate(self.addresses)])
    def tearDown(self): self.tmp.cleanup()
    def fake_get(self,path):
        if path=='/block-height/961640': return builder.CHECKPOINT
        if path=='/blocks/tip/hash': return self.tip
        if path=='/block/'+self.tip: return dict(height=962000)
        if path=='/block-height/962000': return self.tip
        if path=='/tx/'+self.txid+'/hex': return self.raw.hex()
        if path=='/tx/'+self.txid+'/outspends': return [dict(spent=False),dict(spent=True),dict(spent=False)]
        for i,address in enumerate(self.addresses):
            if path=='/address/'+address+'/utxo': return [dict(txid=self.txid,vout=i,value=100000,status=dict(confirmed=i!=2,block_height=961900))]
        raise AssertionError('Unexpected API path')
    def test_builder_excludes_spent_and_unconfirmed_and_validates(self):
        manifest,evidence=builder.collect(self.inventory,self.fake_get,2)
        self.assertEqual(len(manifest['utxos']),1);self.assertEqual(len(evidence['excluded']),2)
        p=self.folder/'manifest.json';p.write_text(json.dumps(manifest))
        coins,_=s.load_manifest(p);self.assertEqual(coins[0].value,100000)
        def wrong_amount(path):
            data=self.fake_get(path)
            if '/address/' in path: data[0]['value']=1
            return data
        with self.assertRaises(ValueError): builder.collect(self.inventory,wrong_amount,2)
        def wrong_chain(path): return '77'*32 if path=='/block-height/961640' else self.fake_get(path)
        with self.assertRaises(ValueError): builder.collect(self.inventory,wrong_chain,2)
    def test_exporter_selected_key_format_and_wallet_checks(self):
        manifest,_=builder.collect(self.inventory,self.fake_get,2)
        mp=self.folder/'manifest.json';mp.write_text(json.dumps(manifest))
        ip=self.folder/'public.json';ip.write_text(json.dumps(self.inventory))
        addresses=self.addresses;scripts=self.scripts
        class Wallet:
            def get_master_public_key(self): return 'zpub-public-test-only'
            def is_watching_only(self): return False
            def derive_address(self,b,i): return addresses[i]
            def has_password(self): return False
            def export_private_key_for_path(self,path,password): return 'p2wpkh:'+cli.wif(path[1]+1)
        fake=types.ModuleType('electrum')
        fake.bitcoin=types.SimpleNamespace(address_to_script=lambda a:scripts[addresses.index(a)].hex(),address_from_private_key=lambda key:addresses[[('p2wpkh:'+cli.wif(i)) for i in (1,2,3)].index(key)])
        previous=sys.modules.get('electrum');sys.modules['electrum']=fake;helpers.wallet=Wallet()
        try:
            output=self.folder/'keys.txt';helpers.export_manifest_keys(mp,ip,output)
            self.assertEqual(len(s.load_keys(output,128)),1)
            with self.assertRaises(ValueError): helpers.export_manifest_keys(mp,ip,output)
            changed=dict(self.inventory,zpub='wrong-wallet');ip.write_text(json.dumps(changed))
            with self.assertRaises(ValueError): helpers.export_manifest_keys(mp,ip,self.folder/'no.txt')
        finally:
            if previous is None: del sys.modules['electrum']
            else: sys.modules['electrum']=previous
    def test_legacy_destination_unified_and_btc_rejection(self):
        dest='1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
        script=s.destination_script(dest,'bc')
        self.assertEqual(script.hex(),'76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')
        coins,_,keys=ref.public_fixture();coins=coins[:1]
        plan=s.make_plan(coins,script,1,Fraction(1),1000,2000,2000)[0]
        self.assertEqual(plan.fee,113)
        raw=s.sign_transaction(coins,plan.output_value,script,keys);tx=ref.decode(raw)
        self.assertEqual(tx['outputs'],[(coins[0].value-113,script)])
        sig,pub=tx['witnesses'][0];spent=[(coins[0].value,coins[0].script)]
        ref.verify(pub,sig[:-1],ref.reference_unified(tx,spent,0))
        for byte in range(256):
            with self.assertRaises(InvalidSignature): ref.verify(pub,sig[:-1],ref.reference_bip143(tx,spent,0,byte))
