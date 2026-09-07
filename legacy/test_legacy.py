"""Synthetic PUBLIC scalars only. No real funds, network or broadcasting."""
import contextlib, hashlib, io, json, pathlib, struct, sys, tempfile, types, unittest
from fractions import Fraction
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import offline_sweep as s
import build_manifest as builder
import electrum_helpers as helpers
def deny(event,args):
    if event.startswith(('socket.','subprocess.','os.exec','os.posix_spawn')) or event=='os.system':
        raise RuntimeError('Network/process forbidden in tests')
sys.addaudithook(deny)
def h(b):return hashlib.sha256(b).digest()
def hh(b):return h(h(b))
def cs(n):
    return bytes([n]) if n<253 else b'\xfd'+n.to_bytes(2,'little') if n<65536 else b'\xfe'+n.to_bytes(4,'little')
def vec(b):return cs(len(b))+b
def out(o):return o[0].to_bytes(8,'little')+vec(o[1])
def decode(raw):
    pos=0
    def take(n):
        nonlocal pos
        r=raw[pos:pos+n];pos+=n;assert len(r)==n;return r
    def number():
        n=take(1)[0];return n if n<253 else int.from_bytes(take({253:2,254:4,255:8}[n]),'little')
    version=take(4);segwit=raw[pos:pos+2]==b'\x00\x01'
    if segwit:take(2)
    inputs=[(take(36),take(number()),take(4)) for _ in range(number())]
    outputs=[(int.from_bytes(take(8),'little'),take(number())) for _ in range(number())]
    if segwit:
        for _ in inputs:
            for __ in range(number()):take(number())
    lock=take(4);assert pos==len(raw)
    return dict(version=version,inputs=inputs,outputs=outputs,lock=lock,segwit=segwit)
def reference_unified(tx,coins,i):
    msg=(b'\x00\x21'+tx['version']+tx['lock']+b'\x00'
        +h(b''.join(x[0] for x in tx['inputs']))+h(b''.join(c.value.to_bytes(8,'little') for c in coins))
        +h(b''.join(vec(c.script) for c in coins))+h(b''.join(x[2] for x in tx['inputs']))
        +h(b''.join(out(o) for o in tx['outputs']))+b'\x00'+i.to_bytes(4,'little')+vec(coins[i].script))
    return h(h(b'UnifiedSighash')*2+msg)
def btc_legacy(tx,coins,index,hash_type):
    base=hash_type&31
    if base==3 and index>=len(tx['outputs']):return b'\x01'+bytes(31)
    ins=[]
    for i,(point,_,sequence) in enumerate(tx['inputs']):
        if i!=index and base in (2,3):sequence=bytes(4)
        ins.append(point+vec(coins[i].script if i==index else b'')+sequence)
    if hash_type&128:ins=[ins[index]]
    outputs=tx['outputs']
    if base==2:outputs=[]
    if base==3:outputs=[(2**64-1,b'')]*index+[outputs[index]]
    return hh(tx['version']+cs(len(ins))+b''.join(ins)+cs(len(outputs))+b''.join(out(o) for o in outputs)+tx['lock']+hash_type.to_bytes(4,'little'))
def key(n):
    private=ec.derive_private_key(n,ec.SECP256K1())
    public=private.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
    script=b'\x76\xa9\x14'+s.hash160(public)+b'\x88\xac'
    return script,s.Key(private,public)
def wif(n):
    raw=b'\x80'+n.to_bytes(32,'big')+b'\x01';num=int.from_bytes(raw+hh(raw)[:4],'big');text=''
    while num:num,r=divmod(num,58);text=s.B58[r]+text
    return text
DEST='1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
class LegacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.p=pathlib.Path(self.tmp.name)
        a,ka=key(1);b,kb=key(2);self.keys={a:ka,b:kb}
        self.coins=[s.Coin('11'*32,0,100000,a),s.Coin('22'*32,1,200000,b)]
        self.dest=s.destination_script(DEST,'bc')
    def tearDown(self):self.tmp.cleanup()
    def test_all_17_published_legacy_vectors(self):
        rows=[r for r in json.loads((pathlib.Path(__file__).parent/'fixtures/unified_sighash.json').read_text())[1:] if r[3:5]==[33,0]]
        self.assertEqual(len(rows),17)
        for code,raw,index,_,_,spent,expected in rows:
            tx=decode(bytes.fromhex(raw))
            prefix=s.unified_all_prefix(int.from_bytes(tx['version'],'little',signed=True),int.from_bytes(tx['lock'],'little'),b''.join(x[0] for x in tx['inputs']),b''.join(v.to_bytes(8,'little') for v,_ in spent),b''.join(vec(bytes.fromhex(script)) for _,script in spent),b''.join(x[2] for x in tx['inputs']),b''.join(out(o) for o in tx['outputs']))
            self.assertEqual(s.unified_legacy_digest(prefix,index,bytes.fromhex(code)).hex(),expected)
    def test_signed_scripts_unified_and_all_btc_hash_types(self):
        raw=s.sign_transaction(self.coins,299000,self.dest,self.keys);tx=decode(raw)
        self.assertFalse(tx['segwit']);self.assertEqual(tx['outputs'],[(299000,self.dest)])
        self.assertEqual(hh(raw)[::-1].hex(),s.parse_transaction(raw).txid)
        for i,(_,script,_) in enumerate(tx['inputs']):
            sig=script[1:1+script[0]];pub=script[2+script[0]:]
            self.assertEqual(sig[-1],33);self.assertEqual(len(pub),33)
            public=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),pub)
            digest=reference_unified(tx,self.coins,i)
            self.assertEqual(digest,s.signature_digests(self.coins,299000,self.dest)[i])
            public.verify(sig[:-1],digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            for byte in range(256):
                with self.assertRaises(InvalidSignature):public.verify(sig[:-1],btc_legacy(tx,self.coins,i,byte),ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            # A correctly signed ordinary legacy control verifies under that reference.
            ordinary=btc_legacy(tx,self.coins,i,1)
            control=self.keys[self.coins[i].script].private.sign(ordinary,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            public.verify(control,ordinary,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            changed=list(self.coins);c=changed[1-i];changed[1-i]=s.Coin(c.txid,c.vout,c.value+1,c.script)
            with self.assertRaises(InvalidSignature):public.verify(sig[:-1],reference_unified(tx,changed,i),ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    def test_weight_fee_bounds_and_reject_wrong_input_type(self):
        self.assertEqual(s.estimated_vsize(1,25),192)
        for count in [1,252,253,600]:
            coins=[s.Coin('33'*32,i,100000,self.coins[0].script) for i in range(count)]
            raw=s.sign_transaction(coins,count*100000-10000,self.dest,self.keys)
            self.assertLessEqual(len(raw)*4,s.estimated_weight(count,25))
        c=self.coins[0];wrong=s.Coin(c.txid,c.vout,c.value,b'\x00\x14'+c.script[3:23])
        with self.assertRaises(s.SweepError):s.signature_digests([wrong],1000,self.dest)
    def fixture(self):
        raw=(b'\x02\x00\x00\x00'+b'\x01'+b'\x55'*32+bytes(4)+b'\x00'+b'\xff'*4+b'\x02'+b''.join(out((c.value,c.script)) for c in self.coins)+bytes(4))
        txid=hh(raw)[::-1].hex()
        manifest=dict(format='offline-p2pkh-sweep/v1',signing_profile=s.PROFILE,snapshot=dict(height=962000,block_hash='66'*32),transactions={txid:raw.hex()},utxos=[dict(txid=txid,vout=i,value_sats=c.value,script_pubkey=c.script.hex()) for i,c in enumerate(self.coins)])
        mp=self.p/'manifest.json';mp.write_text(json.dumps(manifest));kp=self.p/'keys.txt';kp.write_text(wif(1)+'\n'+wif(2)+'\n');kp.chmod(0o600)
        return manifest,mp,kp
    def test_cli_plan_final_txid_and_review_binding(self):
        _,mp,kp=self.fixture();plan=self.p/'plan';signed=self.p/'signed'
        args=['--manifest',str(mp),'--destination',DEST,'--fee-rate','1','--max-tx-fee-sats','2000','--max-total-fee-sats','2000']
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(s.main(args+['--plan-only','--out',str(plan)]),0)
            report=json.loads((plan/'report.json').read_text());self.assertIsNone(report['transactions'][0]['txid'])
            self.assertEqual(s.main(args+['--keys-file',str(kp),'--reviewed-plan',str(plan/'report.json'),'--out',str(signed)]),0)
            done=json.loads((signed/'report.json').read_text());raw=bytes.fromhex((signed/'tx_0001.hex').read_text())
            self.assertEqual(done['transactions'][0]['txid'],hh(raw)[::-1].hex())
            changed=args.copy();changed[changed.index('--fee-rate')+1]='2'
            self.assertEqual(s.main(changed+['--keys-file',str(kp),'--reviewed-plan',str(plan/'report.json'),'--out',str(self.p/'bad')]),2)
    def test_builder_legacy_manifest_and_exporter(self):
        manifest,_,_=self.fixture();txid=next(iter(manifest['transactions']));script=self.coins[0].script.hex()
        inventory=dict(format='electrum-public-inventory/v1',zpub='xpub-public-test',addresses=[dict(branch=0,index=0,address=DEST,script_pubkey=script)])
        def get(path):
            if path=='/block-height/961640':return builder.CHECKPOINT
            if path in ('/blocks/tip/hash','/block-height/962000'):return '66'*32
            if path=='/block/'+'66'*32:return dict(height=962000)
            if path=='/address/'+DEST+'/utxo':return [dict(txid=txid,vout=0,value=100000,status=dict(confirmed=True,block_height=961800))]
            if path=='/tx/'+txid+'/hex':return manifest['transactions'][txid]
            if path=='/tx/'+txid+'/outspends':return [dict(spent=False),dict(spent=False)]
            raise AssertionError(path)
        result,_=builder.collect(inventory,get,1);mp=self.p/'built.json';mp.write_text(json.dumps(result));s.load_manifest(mp)
        ip=self.p/'inventory.json';ip.write_text(json.dumps(inventory))
        class Wallet:
            def get_master_public_key(self):return 'xpub-public-test'
            def is_watching_only(self):return False
            def derive_address(self,b,i):return DEST
            def has_password(self):return False
            def export_private_key_for_path(self,p,password):return 'p2pkh:'+wif(1)
        module=types.ModuleType('electrum');module.bitcoin=types.SimpleNamespace(address_to_script=lambda a:bytes.fromhex(script),address_from_private_key=lambda k:DEST)
        previous=sys.modules.get('electrum');sys.modules['electrum']=module;helpers.wallet=Wallet()
        try:
            kp=self.p/'exported.txt';helpers.export_manifest_keys(mp,ip,kp);loaded=s.load_keys(kp,128)
            self.assertIn(bytes.fromhex(script),loaded)
            with self.assertRaises(ValueError):helpers.export_manifest_keys(mp,ip,kp)
        finally:
            if previous is None:del sys.modules['electrum']
            else:sys.modules['electrum']=previous
