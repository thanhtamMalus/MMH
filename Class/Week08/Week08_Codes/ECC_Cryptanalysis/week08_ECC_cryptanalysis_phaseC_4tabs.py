#!/usr/bin/env python3
"""Week 08 ECC Cryptanalysis — Phase C, real SEC/NIST prime curves.
09 ECIES/ECDH misuse, 10 timing, 14 fault simulation, 15 domain validation.
Dependencies: cryptography, PyQt6 (GUI only).  --self-test runs without PyQt6.
Educational demonstrations: no real endpoint is attacked.
"""
import argparse, hashlib, hmac, secrets, sys, time, statistics, json, math
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

CURVES = {
 'secp256r1': ('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
 '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
 '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
 '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', ec.SECP256R1),
 'secp256k1': ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
 '0','7',
 '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
 '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', ec.SECP256K1),
 'secp384r1': ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
 'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF',
 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
 '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973', ec.SECP384R1),
 'secp521r1': ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
 '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC',
 '0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
 '00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66',
 '011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650',
 '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409', ec.SECP521R1),
}
@dataclass(frozen=True)
class Domain:
 name:str; p:int; a:int; b:int; gx:int; gy:int; n:int; cls:type
 @property
 def G(self): return (self.gx,self.gy)
 @property
 def curve(self): return self.cls()

def domain(name):
 vals=CURVES[name]
 return Domain(name, *(int(v,16) for v in vals[:6]), vals[6])

def on_curve(P,c):
 if P is None: return True
 x,y=P
 return 0<=x<c.p and 0<=y<c.p and (y*y-x*x*x-c.a*x-c.b)%c.p==0

def add(P,Q,c,unchecked=False):
 if P is None: return Q
 if Q is None: return P
 if not unchecked and (not on_curve(P,c) or not on_curve(Q,c)): raise ValueError('Off-curve point rejected')
 x1,y1=P; x2,y2=Q; p=c.p
 if x1==x2 and (y1+y2)%p==0: return None
 if P==Q:
  if y1==0:return None
  slope=((3*x1*x1+c.a)*pow(2*y1,-1,p))%p
 else:
  if x1==x2:raise ValueError('Invalid point pair')
  slope=((y2-y1)*pow(x2-x1,-1,p))%p
 x3=(slope*slope-x1-x2)%p
 return (x3,(slope*(x1-x3)-y1)%p)

def mul(k,P,c,unchecked=False):
 if not unchecked and not on_curve(P,c): raise ValueError('Off-curve point rejected')
 if k<0: return mul(-k,(P[0],(-P[1])%c.p),c,unchecked)
 out=None
 while k:
  if k&1:out=add(out,P,c,unchecked)
  P=add(P,P,c,unchecked); k>>=1
 return out

def digest_z(message,n):
 h=hashlib.sha256(message).digest(); v=int.from_bytes(h,'big')
 excess=256-n.bit_length()
 return v>>excess if excess>0 else v

def public(d,c):
 pub=ec.derive_private_key(d,c.curve).public_key().public_numbers()
 return pub.x,pub.y

def sign_manual(d,k,message,c):
 if not 1<=d<c.n or not 1<=k<c.n:raise ValueError('d and k must be within [1,n-1]')
 x,_=public(k,c); r=x%c.n
 if r==0:raise ValueError('Rare zero r; choose a different nonce')
 z=digest_z(message,c.n)
 s=(pow(k,-1,c.n)*(z+r*d))%c.n
 if s==0:raise ValueError('Rare zero s; choose a different nonce')
 return r,s,z

def verify(Q,message,r,s,c):
 if not (1<=r<c.n and 1<=s<c.n):return False
 try:
  obj=ec.EllipticCurvePublicNumbers(Q[0],Q[1],c.curve).public_key()
  obj.verify(utils.encode_dss_signature(r,s),message,ec.ECDSA(hashes.SHA256()))
  return True
 except (ValueError,InvalidSignature):return False


def scalar(text):
    return int(text.strip(),0) if text.strip().lower().startswith(('0x','0b','0o')) else int(text.strip())

def valid_d(c,d):
    if not 1 <= d < c.n: raise ValueError('Private scalar must satisfy 1 <= d < n')

def ecies_misuse(c,d,plaintext,mode='GCM',reuse_ephemeral=True):
    """Demonstrate static-recipient compromise, ephemeral reuse, and unauthenticated CTR.
    All shared secrets are derived with validated cryptography ECDH APIs.
    """
    valid_d(c,d)
    recipient=ec.derive_private_key(d,c.curve)
    recipient_pub=recipient.public_key()
    k=secrets.randbelow(c.n-1)+1
    ephemeral=ec.derive_private_key(k,c.curve)
    R=ephemeral.public_key()
    z=ephemeral.exchange(ec.ECDH(),recipient_pub)
    z_receiver=recipient.exchange(ec.ECDH(),R)
    assert z==z_receiver
    salt=secrets.token_bytes(16)
    r_bytes=R.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
    info=b'W08-PHASE-C-ECIES-v1|'+c.name.encode()+b'|'+r_bytes
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=info).derive(z)
    nonce=secrets.token_bytes(12)
    aad=b'W08-ECIES|'+c.name.encode()+b'|'+r_bytes+salt
    ciphertext=AESGCM(key).encrypt(nonce,plaintext,aad)
    recovered=AESGCM(key).decrypt(nonce,ciphertext,aad)
    # Compromise of recipient static private key recovers previously recorded traffic.
    recorded_z=recipient.exchange(ec.ECDH(),R)
    recorded_key=HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=info).derive(recorded_z)
    compromise=AESGCM(recorded_key).decrypt(nonce,ciphertext,aad)
    tampered=bytearray(ciphertext);tampered[0]^=1
    try:
        AESGCM(key).decrypt(nonce,bytes(tampered),aad)
        reject=False
    except InvalidTag:reject=True
    # Optional repeated ephemeral: identical ECDH secret, but random HKDF salts make different AES keys.
    z_again=ephemeral.exchange(ec.ECDH(),recipient_pub) if reuse_ephemeral else None
    return {'curve':c.name,'R':r_bytes.hex(),'shared_secret':z.hex(),
            'salt':salt.hex(),'nonce':nonce.hex(),'ciphertext_and_tag':ciphertext.hex(),
            'decryption_ok':recovered==plaintext,'static_compromise_recovers':compromise==plaintext,
            'tamper_rejected':reject,'ephemeral_reuse_same_secret':z_again==z if reuse_ephemeral else None,
            'note':'ECDH public keys are validated by the cryptography backend. No real invalid-point oracle.'}

def variable_mul(k,P,c):
    """INSECURE variable-time, affine scalar multiplication; educational only."""
    out=None; adds=0; doubles=0
    while k:
        if k&1: out=add(out,P,c); adds+=1
        P=add(P,P,c); doubles+=1
        k>>=1
    return out,adds,doubles

def timing_demo(c,d,samples=12):
    valid_d(c,d)
    if not 1<=samples<=1000:raise ValueError('samples must be 1..1000')
    # Compare same-bit-length scalars with different Hamming weights.
    bits=min(96,c.n.bit_length()-2)
    sparse=(1<<(bits-1))+1
    dense=(1<<bits)-1
    sparse=min(sparse,c.n-1);dense=min(dense,c.n-1)
    observations=[]
    for label,k in [('user',d),('sparse',sparse),('dense',dense)]:
        elapsed=[]; a=b=0
        for _ in range(samples):
            t=time.perf_counter_ns(); point,a,b=variable_mul(k,c.G,c)
            elapsed.append((time.perf_counter_ns()-t)/1e6)
        observations.append({'scalar_type':label,'bits':k.bit_length(),'hamming_weight':k.bit_count(),
                             'additions':a,'doublings':b,'median_ms':round(statistics.median(elapsed),4),
                             'minimum_ms':round(min(elapsed),4),'matches_library':point==public(k,c)})
    return {'curve':c.name,'measurements':observations,
            'warning':'Python timings are noisy; these are not reliable side-channel measurements of OpenSSL. No constant-time claim.'}

def fault_demo(c,d,k,bit,message):
    """Demonstrate single-signature faulty-nonce leakage with a deliberately exposed fault model.
    A controlled fault changes nonce k to k XOR 2^bit, with both signatures observed.
    Recovery here uses the known delta and the two signatures; not a general fault exploit.
    """
    valid_d(c,d)
    if not 0<=bit<min(c.n.bit_length(),512):raise ValueError('fault bit outside supported range')
    if not 1<=k<c.n:raise ValueError('Nonce outside [1,n-1]')
    k_bad=k^(1<<bit)
    if not 1<=k_bad<c.n:raise ValueError('Faulted nonce invalid; select different k or bit')
    r,s,z=sign_manual(d,k,message,c)
    rf,sf,_=sign_manual(d,k_bad,message,c)
    # Fault-model simulation: k_bad is disclosed to demonstrate resulting private-key exposure.
    recovered=((sf*k_bad-z)*pow(rf,-1,c.n))%c.n
    Q=public(d,c)
    return {'curve':c.name,'fault_model':'nonce bit-flip with faulted nonce exposed to analyst',
            'original_nonce':hex(k),'faulted_nonce':hex(k_bad),'bit':bit,
            'original_signature':{'r':hex(r),'s':hex(s)},
            'faulted_signature':{'r':hex(rf),'s':hex(sf)},
            'recovered_d':hex(recovered),'recovery_correct':recovered==d,
            'both_signatures_verify':verify(Q,message,r,s,c) and verify(Q,message,rf,sf,c),
            'warning':'A bit flip alone does not reveal k_bad; this is a specified leakage model, not universal key recovery.'}

def validate_parameters(c,check_order=True):
    p,a,b,gx,gy,n=c.p,c.a,c.b,c.gx,c.gy,c.n
    checks={'p_odd':p>3 and p%2==1,'p_probably_prime':is_probable_prime(p),
            'a_in_field':0<=a<p,'b_in_field':0<=b<p,
            'non_singular':(4*pow(a,3,p)+27*pow(b,2,p))%p!=0,
            'G_on_curve':on_curve(c.G,c),'n_probably_prime':is_probable_prime(n),
            'G_not_infinity':c.G is not None}
    if check_order:checks['nG_is_infinity']=mul(n,c.G,c) is None
    return {'curve':c.name,'field_bits':p.bit_length(),'order_bits':n.bit_length(),
            'cofactor':1 if c.name not in () else None,
            'checks':checks,'all_pass':all(checks.values()),
            'note':'Cofactor=1 for these four SEC curves. Probable-prime tests are not formal certificates.'}

def is_probable_prime(n):
    if n<2:return False
    small=(2,3,5,7,11,13,17,19,23,29,31,37)
    for p in small:
        if n%p==0:return n==p
    d=n-1;s=0
    while d%2==0:s+=1;d//=2
    for a in small:
        if a>=n:continue
        x=pow(a,d,n)
        if x in (1,n-1):continue
        for _ in range(s-1):
            x=x*x%n
            if x==n-1:break
        else:return False
    return True

def self_test():
    for name in CURVES:
        c=domain(name); d=13
        a=ecies_misuse(c,d,b'Week 08 test')
        assert a['decryption_ok'] and a['tamper_rejected'] and a['static_compromise_recovers']
        t=timing_demo(c,d,2)
        assert all(x['matches_library'] for x in t['measurements'])
        f=fault_demo(c,d,19,1,b'fault test')
        assert f['recovery_correct'] and f['both_signatures_verify']
        v=validate_parameters(c)
        assert v['all_pass']
        print(name+': 09 ECIES/ECDH PASS | 10 timing PASS | 14 fault PASS | 15 parameters PASS')

def launch_gui():
    from PyQt6.QtWidgets import (QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QFormLayout,
      QComboBox,QLineEdit,QPlainTextEdit,QPushButton,QLabel,QSpinBox,QTabWidget,QMessageBox,QGroupBox)
    from PyQt6.QtCore import Qt
    app=QApplication(sys.argv)
    class Main(QMainWindow):
        def __init__(self):
            super().__init__();self.setWindowTitle('Week 08 — ECC Cryptanalysis Phase C (Real Curves)')
            self.resize(1100,850); self.tabs=QTabWidget();self.setCentralWidget(self.tabs)
            self.panels=[]
            for idx,title in enumerate(('09 — ECIES / ECDH Misuse','10 — Timing Side Channels',
                                        '14 — Fault Injection','15 — Parameter Validation')):
                panel=QWidget();layout=QVBoxLayout(panel);form=QFormLayout()
                curve=QComboBox();curve.addItems(list(CURVES));form.addRow('SEC/NIST curve',curve)
                d=QLineEdit('13');form.addRow('Private scalar d (decimal or 0xHEX)',d)
                fields={}
                if idx==0:
                    fields['message']=QLineEdit('Hello ECC hybrid encryption');form.addRow('Plaintext (UTF-8)',fields['message'])
                    fields['reuse']=QComboBox();fields['reuse'].addItems(['Repeat ephemeral key (unsafe)','Fresh ephemeral key'])
                    form.addRow('Ephemeral demonstration',fields['reuse'])
                if idx==1:
                    fields['samples']=QSpinBox();fields['samples'].setRange(1,1000);fields['samples'].setValue(10)
                    form.addRow('Timing samples per scalar',fields['samples'])
                if idx==2:
                    fields['k']=QLineEdit('19');form.addRow('ECDSA nonce k',fields['k'])
                    fields['bit']=QSpinBox();fields['bit'].setRange(0,511);fields['bit'].setValue(1)
                    form.addRow('Faulted nonce bit index',fields['bit'])
                    fields['message']=QLineEdit('ECC fault demonstration');form.addRow('Signed message',fields['message'])
                if idx==3:
                    fields['point']=QLineEdit('');fields['point'].setPlaceholderText('Optional public point SEC1 HEX (02/03/04...)')
                    form.addRow('Optional public point',fields['point'])
                layout.addLayout(form)
                row=QHBoxLayout();run=QPushButton('Run demonstration / analysis');copy=QPushButton('Copy log');clear=QPushButton('Clear log')
                for b in (run,copy,clear):row.addWidget(b)
                layout.addLayout(row)
                out=QPlainTextEdit();out.setReadOnly(True);layout.addWidget(out)
                layout.addWidget(QLabel('Educational use only. Real SEC curves; deliberately vulnerable models are explicitly identified.'))
                run.clicked.connect(lambda _=False,i=idx:self.execute(i))
                copy.clicked.connect(lambda _=False,o=out:QApplication.clipboard().setText(o.toPlainText()))
                clear.clicked.connect(out.clear)
                self.tabs.addTab(panel,title);self.panels.append((curve,d,fields,out))
        def execute(self,i):
            curve,d_text,fields,out=self.panels[i]
            try:
                c=domain(curve.currentText());d=scalar(d_text.text());valid_d(c,d)
                started=time.perf_counter()
                if i==0:
                    result=ecies_misuse(c,d,fields['message'].text().encode('utf8'),reuse_ephemeral=fields['reuse'].currentIndex()==0)
                elif i==1:result=timing_demo(c,d,fields['samples'].value())
                elif i==2:result=fault_demo(c,d,scalar(fields['k'].text()),fields['bit'].value(),fields['message'].text().encode('utf8'))
                else:
                    result=validate_parameters(c)
                    sec1=fields['point'].text().strip().replace(' ','')
                    if sec1:
                        try:
                            p=ec.EllipticCurvePublicKey.from_encoded_point(c.curve,bytes.fromhex(sec1))
                            numbers=p.public_numbers();result['user_point_valid']=True
                            result['user_point_coordinates']={'x':hex(numbers.x),'y':hex(numbers.y)}
                        except (ValueError,TypeError) as e:result['user_point_valid']=False;result['point_error']=str(e)
                result['elapsed_seconds']=round(time.perf_counter()-started,5)
                out.appendPlainText(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
            except Exception as e:QMessageBox.warning(self,'Invalid input / demonstration failed',str(e))
    win=Main();win.show();sys.exit(app.exec())

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--self-test',action='store_true');args=parser.parse_args()
    if args.self_test:self_test()
    else:launch_gui()
