#!/usr/bin/env python3
"""Week 08 Phase B: real-curve ECC implementation vulnerabilities.
Dependencies: pip install PyQt6 cryptography
Run --self-test to exercise all four demonstrations without PyQt6.
Educational simulations only; never use manual ECDSA or unchecked EC multiplication in production.
"""
import argparse
import hashlib
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Standard SEC/NIST prime-field domain parameters. G and n come from published standards.
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

def invalid_curve_demo(c,d):
 # x=0, y=0 gives order-two point on altered y²=x³+a*x+b' with b'=0.
 # On all provided real curves b != 0, so (0,0) is off the original curve.
 P=(0,0)
 assert not on_curve(P,c) and c.b!=0
 leaked=mul(d,P,c,unchecked=True)
 rejected=False
 try:mul(d,P,c)
 except ValueError:rejected=True
 return {'point':P,'altered_b':0,'order':2,'oracle_output':leaked,'parity':d%2,'rejected':rejected}

def reuse_demo(c,d,k,m1,m2):
 if m1==m2:raise ValueError('Messages must differ')
 r1,s1,z1=sign_manual(d,k,m1,c);r2,s2,z2=sign_manual(d,k,m2,c)
 if r1!=r2 or s1==s2:raise ValueError('Degenerate example; change nonce/messages')
 recovered_k=((z1-z2)*pow((s1-s2)%c.n,-1,c.n))%c.n
 recovered_d=((s1*recovered_k-z1)*pow(r1,-1,c.n))%c.n
 Q=public(d,c)
 return dict(r=r1,s1=s1,s2=s2,z1=z1,z2=z2,k=recovered_k,d=recovered_d,valid=verify(Q,m1,r1,s1,c) and verify(Q,m2,r2,s2,c) and recovered_d==d)

def partial_nonce_demo(c,d,k,unknown_bits,m,budget,log=None):
 if not 0<=unknown_bits<=min(32,c.n.bit_length()-1):raise ValueError('Unknown bits must be between 0 and 32 (and below n bits)')
 if budget<=0:raise ValueError('Work budget must be positive')
 r,s,z=sign_manual(d,k,m,c); Q=public(d,c)
 # Attacker learns all nonce bits except its lowest t bits. This is a strong
 # leakage assumption; one signature then suffices for bounded enumeration.
 upper=k>>unknown_bits; count=1<<unknown_bits
 s_inv=pow(s,-1,c.n); r_inv=pow(r,-1,c.n)
 checked=0
 for low in range(min(count,budget)):
  guess=(upper<<unknown_bits)|low
  if not 1<=guess<c.n:continue
  checked+=1
  cand=((s*guess-z)*r_inv)%c.n
  if cand and public(cand,c)==Q:
   return dict(found=True,d=cand,k=guess,checked=checked,total=count,r=r,s=s,upper=upper,valid=verify(Q,m,r,s,c))
 return dict(found=False,checked=checked,total=count,r=r,s=s,upper=upper)

def malleability_demo(c,d,k,m):
 r,s,z=sign_manual(d,k,m,c); alt=c.n-s; Q=public(d,c)
 return dict(r=r,s=s,s_alt=alt,original_ok=verify(Q,m,r,s,c),alternate_ok=verify(Q,m,r,alt,c),low_s=min(s,alt),high_s=max(s,alt))

def self_test():
 for name in CURVES:
  c=domain(name)
  assert on_curve(c.G,c) and mul(c.n,c.G,c) is None
  assert public(2,c)==mul(2,c.G,c)
  assert invalid_curve_demo(c,37)['parity']==1
  x=reuse_demo(c,37,83,b'first',b'second');assert x['valid'] and x['d']==37 and x['k']==83
  y=partial_nonce_demo(c,37,83,9,b'partial',1000);assert y['found'] and y['d']==37
  z=malleability_demo(c,37,83,b'malleable');assert z['original_ok'] and z['alternate_ok']
  print(f'PASS {name}: curve/group, invalid-point, nonce reuse, partial leakage, malleability')

# GUI loaded only when needed so --self-test works without PyQt6.
def launch_gui():
 from PyQt6.QtCore import Qt
 from PyQt6.QtWidgets import (QApplication,QWidget,QMainWindow,QVBoxLayout,QHBoxLayout,QFormLayout,
  QTabWidget,QComboBox,QLineEdit,QTextEdit,QPushButton,QLabel,QSpinBox,QMessageBox,QGroupBox,QScrollArea)
 class Lab(QMainWindow):
  def __init__(self):
   super().__init__();self.setWindowTitle('Week 08 — Phase B: Vulnerable ECC Implementations (Real SEC Curves)');self.resize(1150,790)
   self.tabs=QTabWidget();self.setCentralWidget(self.tabs);self.controls=[]
   self.names=['05 — Invalid Curve / Small Subgroup','06 — ECDSA Nonce Reuse','07 — Partial ECDSA Nonce Leakage','08 — ECDSA Signature Malleability']
   for i,name in enumerate(self.names):self.add_tab(i,name)
   self.statusBar().showMessage('Real SEC/NIST curves. Vulnerable operations are deliberately simulated; not production implementations.')
  def add_tab(self,i,name):
   w=QWidget();root=QVBoxLayout(w);root.setSpacing(9)
   heading=QLabel(name);heading.setStyleSheet('font-size:18px;font-weight:bold');root.addWidget(heading)
   intro=[
    'Off-curve point P=(0,0) has order 2 on a different curve with the same p,a. An unchecked scalar-multiplication oracle leaks d mod 2. Proper point validation rejects P.',
    'Two different ECDSA messages signed with identical nonce k expose the private scalar d. The attack uses only signatures and message digests.',
    'Demonstrates a strong nonce-leakage model: the attacker knows all bits of k except the lowest t bits. Enumerate the unknown bits and validate the recovered public key.',
    'ECDSA permits (r,s) and (r,n-s) for the same message/public key. Explore low-s canonicalization and signature malleability.'
   ][i]
   label=QLabel(intro);label.setWordWrap(True);root.addWidget(label)
   form=QFormLayout();curve=QComboBox();curve.addItems(CURVES.keys());form.addRow('Standard curve:',curve)
   d=QLineEdit('37');d.setToolTip('Decimal or 0x-prefixed hexadecimal; 1 <= d < n');form.addRow('Private scalar d:',d)
   nonce=QLineEdit('83');nonce.setToolTip('ECDSA nonce; 1 <= k < n');
   if i in (1,2,3):form.addRow('ECDSA nonce k:',nonce)
   msg=QLineEdit('Week08 ECC laboratory');msg2=QLineEdit('Second distinct message')
   if i in (1,2,3):form.addRow('Message 1 (UTF-8):',msg)
   if i==1:form.addRow('Message 2 (UTF-8):',msg2)
   bits=QSpinBox();bits.setRange(0,32);bits.setValue(12)
   budget=QLineEdit('100000');
   if i==2:
    form.addRow('Unknown low nonce bits:',bits);form.addRow('Maximum candidate attempts:',budget)
   root.addLayout(form)
   bar=QHBoxLayout();run=QPushButton('Run Demonstration');copy=QPushButton('Copy Log');clear=QPushButton('Clear Log');bar.addWidget(run);bar.addWidget(copy);bar.addWidget(clear);root.addLayout(bar)
   log=QTextEdit();log.setReadOnly(True);log.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap);log.setStyleSheet('font-family:Consolas,monospace;font-size:12px');root.addWidget(log,1)
   self.tabs.addTab(w,name);self.controls.append((curve,d,nonce,msg,msg2,bits,budget,log))
   run.clicked.connect(lambda checked=False,j=i:self.run(j));copy.clicked.connect(lambda checked=False,t=log:QApplication.clipboard().setText(t.toPlainText()));clear.clicked.connect(log.clear)
  def run(self,i):
   curve,d_field,k_field,m1_field,m2_field,bits,budget_field,log=self.controls[i]
   try:
    c=domain(curve.currentText());d=int(d_field.text().strip(),0) if d_field.text().strip().lower().startswith('0x') else int(d_field.text().strip())
    if not 1<=d<c.n:raise ValueError('Private scalar must satisfy 1 <= d < n')
    k=0
    if i in (1,2,3):
     t=k_field.text().strip();k=int(t,0) if t.lower().startswith('0x') else int(t)
     if not 1<=k<c.n:raise ValueError('Nonce must satisfy 1 <= k < n')
    m=m1_field.text().encode('utf-8');m2=m2_field.text().encode('utf-8')
    lines=[f'Curve: {c.name}',f'Field p = 0x{c.p:X}',f'Curve y² = x³ + ax + b (mod p)',f'a = 0x{c.a:X}',f'b = 0x{c.b:X}',f'Generator order n = 0x{c.n:X}',f'Q = [d]G = {public(d,c)}','']
    start=time.perf_counter()
    if i==0:
     res=invalid_curve_demo(c,d)
     lines+=['ATTACK: unchecked scalar multiplication on off-curve input','Off-curve P = (0,0)',"P lies on altered curve with b'=0 (not the selected curve).",'Order of P on altered curve: 2',f'Unchecked oracle [d]P = {res["oracle_output"]}',f'Information disclosed: d mod 2 = {res["parity"]}',f'Validated multiplication rejects P: {res["rejected"]}', 'Note: this one-query demonstration leaks only one bit, not the entire private key.']
    elif i==1:
     res=reuse_demo(c,d,k,m,m2)
     lines+=['ATTACK: same nonce across two different messages',f'r1 = r2 = 0x{res["r"]:X}',f's1 = 0x{res["s1"]:X}',f's2 = 0x{res["s2"]:X}',f'z1 = 0x{res["z1"]:X}',f'z2 = 0x{res["z2"]:X}', 'k = (z1-z2)/(s1-s2) mod n',f'Recovered k = {res["k"]}','d = (s1*k-z1)/r mod n',f'Recovered d = {res["d"]}',f'Independent signature and key verification: {res["valid"]}']
    elif i==2:
     t=budget_field.text().strip();b=int(t,0) if t.lower().startswith('0x') else int(t)
     if bits.value()>24 and b>1000000:
      choice=QMessageBox.question(self,'Large computation',f'This may require up to {min(1<<bits.value(),b):,} public-key computations. Continue?')
      if choice!=QMessageBox.StandardButton.Yes:return
     res=partial_nonce_demo(c,d,k,bits.value(),m,b)
     lines+=['ATTACK: all nonce bits known except lowest t bits',f't = {bits.value()}',f'Known high bits of nonce: 0x{res["upper"]:X}',f'Possible low-bit candidates: {res["total"]:,}',f'Candidate attempts performed: {res["checked"]:,}',f'Signature r = 0x{res["r"]:X}',f'Signature s = 0x{res["s"]:X}',f'Private key recovered: {res["found"]}']
     if res['found']:lines += [f'Recovered nonce k = {res["k"]}',f'Recovered private scalar d = {res["d"]}',f'Signature verified: {res["valid"]}']
     else:lines+=['Increase work budget or reduce unknown bits to complete this demonstration.','This is exhaustive search over leaked nonce bits, not a lattice/HNP attack.']
    else:
     res=malleability_demo(c,d,k,m)
     lines+=['ATTACK: ECDSA signature malleability',f'r = 0x{res["r"]:X}',f's = 0x{res["s"]:X}',f'Alternative s\' = n-s = 0x{res["s_alt"]:X}',f'Original verifies: {res["original_ok"]}',f'Alternative verifies: {res["alternate_ok"]}',f'Canonical low-s = 0x{res["low_s"]:X}',f'Noncanonical high-s = 0x{res["high_s"]:X}', 'A protocol may require low-s to prevent multiple valid encodings of a signature.']
    lines+=['',f'Elapsed: {time.perf_counter()-start:.6f} s','WARNING: Educational demonstrations; never deploy manual ECDSA or unchecked point operations.']
    log.append('\n'.join(lines)+'\n'+'='*70+'\n')
   except Exception as exc:QMessageBox.warning(self,'Invalid parameters / demonstration failed',str(exc))
 app=QApplication(sys.argv);win=Lab();win.show();sys.exit(app.exec())

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--self-test',action='store_true');args=parser.parse_args()
 if args.self_test:self_test()
 else:launch_gui()
