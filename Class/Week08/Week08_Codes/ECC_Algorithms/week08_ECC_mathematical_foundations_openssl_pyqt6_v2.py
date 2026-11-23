"""Week 08 — ECC Mathematical Foundations laboratory.
OpenSSL named-curve discovery and parameter inspection; Python prime and binary field group arithmetic.
Educational reversible message-to-point encoding, NOT hash-to-curve or production encryption.
Requires: pip install PyQt6; OpenSSL 3.x on PATH.
"""
from __future__ import annotations
import re, shutil, subprocess, sys
from pathlib import Path
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QApplication,QMainWindow,QWidget,QTabWidget,QVBoxLayout,QHBoxLayout,
 QFormLayout,QGroupBox,QLabel,QLineEdit,QPushButton,QTextEdit,QComboBox,QFileDialog,QMessageBox,QSpinBox)
PREFERRED=['prime256v1','secp384r1','secp521r1','secp256k1','secp224r1','secp192r1','brainpoolP256r1','brainpoolP384r1','brainpoolP512r1','SM2','sect163r2','sect233r1','sect283r1','sect409r1','sect571r1']
def hbytes(text):
    s=''.join(text.split()).replace(':','')
    if s.lower().startswith('0x'):s=s[2:]
    if len(s)%2:raise ValueError('Hexadecimal data must have an even number of digits')
    return bytes.fromhex(s)

def pretty(n):
    s=f'{n:x}';s=('0' if len(s)%2 else '')+s
    return '\n'.join(s[i:i+64] for i in range(0,len(s),64))

def write_data(path,data,fmt):
    if fmt=='Binary (.bin)':path.write_bytes(data)
    else:path.write_text('\n'.join(data.hex()[i:i+64] for i in range(0,len(data.hex()),64))+'\n',encoding='utf-8')

def read_data(path,fmt):
    return path.read_bytes() if fmt=='Binary (.bin)' else hbytes(path.read_text(encoding='utf-8'))

# Unified prime/binary-field mathematical engine.
# Field modulus is p for prime fields, irreducible polynomial f(t) for binary fields.
from dataclasses import dataclass
import random

@dataclass(frozen=True)
class Curve:
    kind: str
    modulus: int
    a: int
    b: int
    G: tuple
    n: int
    h: int
    name: str = ''
    @property
    def degree(self): return self.modulus.bit_length()-1
    @property
    def width(self): return (self.degree+7)//8 if self.kind=='binary' else (self.modulus.bit_length()+7)//8
    @property
    def q(self): return (1<<self.degree) if self.kind=='binary' else self.modulus

class Field:
    def __init__(self,C): self.C=C; self.mod=C.modulus; self.m=C.degree; self.mask=(1<<self.m)-1
    def add(self,x,y): return x^y if self.C.kind=='binary' else (x+y)%self.mod
    def sub(self,x,y): return x^y if self.C.kind=='binary' else (x-y)%self.mod
    def mul(self,x,y):
        if self.C.kind!='binary':return x*y%self.mod
        r=0
        while y:
            if y&1:r^=x
            y>>=1;x<<=1
            if x>>self.m:x^=self.mod
        return r
    def sq(self,x):return self.mul(x,x)
    def inv(self,x):
        if not x:raise ZeroDivisionError('Division by zero in finite field')
        if self.C.kind!='binary':return pow(x,-1,self.mod)
        u,v=x,self.mod;g1,g2=1,0
        while u!=1:
            if u==0:raise ValueError('Non-invertible polynomial; invalid field modulus')
            j=u.bit_length()-v.bit_length()
            if j<0:u,v=v,u;g1,g2=g2,g1;j=-j
            u^=v<<j;g1^=g2<<j
        return self.reduce(g1)
    def reduce(self,x):
        while x.bit_length()>self.m:x^=self.mod<<(x.bit_length()-self.m-1)
        return x
    def div(self,x,y):return self.mul(x,self.inv(y))
    def sqrt(self,x):
        if self.C.kind!='binary':
            if x==0:return 0
            p=self.mod
            if pow(x,(p-1)//2,p)!=1:return None
            if p%4==3:return pow(x,(p+1)//4,p)
            q=p-1;s=0
            while q%2==0:q//=2;s+=1
            z=2
            while pow(z,(p-1)//2,p)!=p-1:z+=1
            c=pow(z,q,p);r=pow(x,(q+1)//2,p);t=pow(x,q,p);m=s
            while t!=1:
                i=1;v=t*t%p
                while i<m and v!=1:v=v*v%p;i+=1
                if i==m:return None
                u=pow(c,1<<(m-i-1),p);r=r*u%p;t=t*u*u%p;c=u*u%p;m=i
            return r
        for _ in range(self.m-1):x=self.sq(x)
        return x
    def quadratic(self,c):
        # Solve z^2+z=c over GF(2^m); trace(c)=0 is required.
        if c==0:return 0
        if self.m%2:
            z=c
            for _ in range((self.m-1)//2):z=self.sq(self.sq(z))^c
            return z if self.sq(z)^z==c else None
        # Even-degree probabilistic quadratic solver, deterministic local RNG.
        rng=random.Random(c^self.mod)
        for _ in range(32):
            t=rng.randrange(1,1<<self.m);z=0;w=c
            for _ in range(1,self.m):
                z=self.sq(z)^self.mul(self.sq(w),t)
                w=self.sq(w)^c
            if w==0 and self.sq(z)^z==c:return z
        return None

def neg(P,C):
    if P is None:return None
    x,y=P
    return (x,x^y) if C.kind=='binary' else (x,(-y)%C.modulus)

def add(P,Q,C):
    if P is None:return Q
    if Q is None:return P
    f=Field(C);x,y=P;u,v=Q
    if C.kind=='binary':
        if x==u:
            if y^v==x:return None
            if y!=v:raise ValueError('Invalid same-x binary-curve points')
            if x==0:return None
            lam=x^f.div(y,x)
            xr=f.sq(lam)^lam^C.a
            yr=f.sq(x)^f.mul(lam^1,xr)
        else:
            lam=f.div(y^v,x^u)
            xr=f.sq(lam)^lam^x^u^C.a
            yr=f.mul(lam,x^xr)^xr^y
        return xr,yr
    p=C.modulus
    if x==u and (y+v)%p==0:return None
    if P==Q:
        lam=f.div((3*x*x+C.a)%p,(2*y)%p)
    else:lam=f.div((v-y)%p,(u-x)%p)
    xr=(lam*lam-x-u)%p
    return xr,(lam*(x-xr)-y)%p

def mul(k,P,C):
    if k<0:return mul(-k,neg(P,C),C)
    R=None
    while k:
        if k&1:R=add(R,P,C)
        P=add(P,P,C);k>>=1
    return R

def on_curve(P,C):
    if P is None:return True
    x,y=P;f=Field(C)
    if not (0<=x<C.q and 0<=y<C.q):return False
    if C.kind=='binary':
        return f.sq(y)^f.mul(x,y)==f.mul(f.sq(x),x)^f.mul(C.a,f.sq(x))^C.b
    return (y*y-x*x*x-C.a*x-C.b)%C.modulus==0

def solve_y(x,C):
    f=Field(C)
    if not 0<=x<C.q:return None
    if C.kind=='binary':
        if x==0:return f.sqrt(C.b)
        x2=f.sq(x)
        z=f.quadratic(x^C.a^f.div(C.b,x2))
        return None if z is None else f.mul(x,z)
    return f.sqrt((pow(x,3,C.modulus)+C.a*x+C.b)%C.modulus)

def encode(P,C,compressed=False):
    if P is None:raise ValueError('Cannot serialize infinity as SEC1 point')
    x,y=P;L=C.width
    if not on_curve(P,C):raise ValueError('Point not on selected curve')
    if compressed:
        if C.kind=='binary': bit=0 if x==0 else (Field(C).div(y,x)&1)
        else:bit=y&1
        return bytes([2+bit])+x.to_bytes(L,'big')
    return b'\x04'+x.to_bytes(L,'big')+y.to_bytes(L,'big')

def decode(data,C):
    L=C.width
    if len(data)==1+2*L and data[0]==4:
        P=(int.from_bytes(data[1:1+L],'big'),int.from_bytes(data[1+L:],'big'))
    elif len(data)==1+L and data[0] in (2,3):
        x=int.from_bytes(data[1:],'big');bit=data[0]&1
        y=solve_y(x,C)
        if y is None:raise ValueError('No point for this compressed x coordinate')
        if C.kind=='binary':
            if x==0:
                if bit:raise ValueError('Invalid compressed SEC1 bit for x=0')
            elif (Field(C).div(y,x)&1)!=bit:y^=x
        else:
            if (y&1)!=bit:y=(-y)%C.modulus
        P=x,y
    else:raise ValueError('Expected SEC1 compressed/uncompressed point')
    if not on_curve(P,C):raise ValueError('SEC1 point fails curve equation')
    return P

POINT_MAGIC=1

def point_payload_capacity(C):return C.width-5

def encode_message_point(raw,C):
    cap=point_payload_capacity(C)
    if cap<1 or len(raw)>cap:raise ValueError(f'Message length {len(raw)} exceeds {cap} bytes for {C.name}; use a shorter message or ECIES')
    prefix=bytes([POINT_MAGIC])+len(raw).to_bytes(2,'big')+raw.ljust(cap,b'\x00')
    for counter in range(65536):
        x=int.from_bytes(prefix+counter.to_bytes(2,'big'),'big')
        if x>=C.q:continue
        y=solve_y(x,C)
        if y is None:continue
        P=x,y
        return P,counter
    raise ValueError('Could not find a point in the generator subgroup after 65536 attempts')

def decode_message_point(P,C):
    if P is None or not on_curve(P,C):raise ValueError('Invalid curve point')
    buf=P[0].to_bytes(C.width,'big');cap=point_payload_capacity(C)
    if buf[0]!=POINT_MAGIC:raise ValueError('Point is not Week 8 encoded plaintext')
    length=int.from_bytes(buf[1:3],'big')
    if length>cap:raise ValueError('Invalid embedded length')
    padded=buf[3:3+cap]
    if any(padded[length:]):raise ValueError('Invalid embedded padding')
    return padded[:length],int.from_bytes(buf[-2:],'big')

class Window(QMainWindow):
 def __init__(self):
  super().__init__();self.setWindowTitle('Week 08 — ECC Mathematical Foundations | OpenSSL + PyQt6');self.resize(1280,900)
  self.ssl=shutil.which('openssl') or 'openssl';self.cache={};self.last_point=None;self.last_bytes=None;self.last_curve=None
  self.tabs=QTabWidget();self.setCentralWidget(self.tabs)
  for title,method in [('1. OpenSSL',self.tab1),('2. Curves and Parameters',self.tab2),('3. Group and Subgroup',self.tab3),('4. ECC Arithmetic',self.tab4),('5. Scalar Multiplication',self.tab5),('6. Message to Point',self.tab6),('7. Point to Message',self.tab7)]:self.tabs.addTab(method(),title)
  self.safe(self.discover)
 def safe(self,fn):
  try:fn()
  except Exception as e:
   message=str(e)
   
   QMessageBox.warning(self,'ECC laboratory — operation unavailable',message)
 def run(self,*args):
  cmd=[self.path.text().strip() or 'openssl',*map(str,args)]
  cp=subprocess.run(cmd,capture_output=True)
  if cp.returncode:raise RuntimeError('OpenSSL command failed: '+' '.join(cmd)+'\n'+cp.stderr.decode(errors='replace'))
  return cp.stdout.decode(errors='replace')
 def page(self,description):
  w=QWidget();l=QVBoxLayout(w);t=QLabel(description);t.setWordWrap(True);l.addWidget(t);return w,l
 def form(self,l,title):
  b=QGroupBox(title);f=QFormLayout(b);l.addWidget(b);return f
 def btn(self,l,title,fn):
  b=QPushButton(title);b.clicked.connect(lambda:self.safe(fn));l.addWidget(b)
 def log(self,l):
  o=QTextEdit();o.setReadOnly(True);o.setFont(QFont('Consolas',11));l.addWidget(o);return o
 def entry(self,f,label,default=''):
  e=QLineEdit(default);f.addRow(label,e);return e
 def combo(self,f,label,items):
  c=QComboBox();c.addItems(items);f.addRow(label,c);return c
 def curve_name(self):return self.curves.currentText()
 def params(self):
  name=self.curve_name()
  if name not in self.cache:self.cache[name]=self.parse_curve(name)
  return self.cache[name]
 def parse_curve(self,name):
  t=self.run('ecparam','-name',name,'-param_enc','explicit','-text','-noout')
  binary=bool(re.search(r'Field Type:\s*characteristic-two-field',t,re.I))
  prime=bool(re.search(r'Field Type:\s*prime-field',t,re.I))
  if not binary and not prime:raise ValueError('Unsupported field representation: '+name)
  lines=t.splitlines()
  def integer(heading):
   ix=next((i for i,line in enumerate(lines) if re.match(r'^\s*'+re.escape(heading)+r'\s*:',line,re.I)),None)
   if ix is None:raise ValueError('Missing parameter '+heading)
   suffix=lines[ix].split(':',1)[1].strip()
   m=re.match(r'^(\d+)\s*(?:\(0x[0-9a-fA-F]+\))?$',suffix)
   if m:return int(m.group(1))
   if re.fullmatch(r'0x[0-9a-fA-F]+',suffix):return int(suffix,16)
   parts=[]
   for line in lines[ix+1:]:
    z=line.strip()
    if re.fullmatch(r'(?:[0-9a-fA-F]{2}:)*[0-9a-fA-F]{2}:?',z):parts.extend(re.findall(r'[0-9a-fA-F]{2}',z))
    elif parts:break
    elif z:raise ValueError(f'Unexpected {heading} parameter: {z}')
   if not parts:raise ValueError('Missing bytes for '+heading)
   return int(''.join(parts),16)
  modulus=integer('Polynomial' if binary else 'Prime')
  a=integer('A');b=integer('B');n=integer('Order');h=integer('Cofactor')
  if binary:
   if not re.search(r'Basis Type:\s*(?:ppBasis|tpBasis)',t):raise ValueError('Only polynomial-basis binary curves are supported')
   degree=modulus.bit_length()-1
   if degree<2:raise ValueError('Invalid binary field polynomial')
   a&=(1<<degree)-1;b&=(1<<degree)-1
  else:a%=modulus;b%=modulus
  gi=next((i for i,line in enumerate(lines) if re.match(r'^\s*Generator\s*\(',line,re.I)),None)
  if gi is None:raise ValueError('Missing SEC1 generator')
  octets=[]
  for line in lines[gi+1:]:
   z=line.strip()
   if re.fullmatch(r'(?:[0-9a-fA-F]{2}:)*[0-9a-fA-F]{2}:?',z):octets.extend(re.findall(r'[0-9a-fA-F]{2}',z))
   elif octets:break
   elif z:raise ValueError('Unexpected generator encoding')
  provisional=Curve('binary' if binary else 'prime',modulus,a,b,(0,0),n,h,name)
  G=decode(bytes.fromhex(''.join(octets)),provisional)
  C=Curve(provisional.kind,modulus,a,b,G,n,h,name)
  if not binary and (4*pow(a,3,modulus)+27*pow(b,2,modulus))%modulus==0:raise ValueError('Singular prime-field curve')
  if binary and b==0:raise ValueError('Singular binary-field curve (b=0)')
  if mul(n,G,C) is not None:raise ValueError('Generator order verification failed: [n]G != O')
  return C
 def point(self,text):
  s=text.strip()
  if s.upper() in ('O','INF','INFINITY','∞'):return None
  return decode(hbytes(s),self.params())
 def showpoint(self,P):
  if P is None:return 'O (point at infinity)'
  C=self.params()
  return f'x = 0x{P[0]:x}\ny = 0x{P[1]:x}\nSEC1 uncompressed: {encode(P,C).hex()}\nSEC1 compressed: {encode(P,C,True).hex()}'
 def tab1(self):
  w,l=self.page('Configure the OpenSSL executable. Curve discovery uses openssl ecparam -list_curves.');f=self.form(l,'OpenSSL executable');self.path=self.entry(f,'Executable:',self.ssl)
  self.btn(l,'Test OpenSSL',lambda:self.o1.setPlainText(self.run('version','-a')+'\n'+self.run('list','-providers')));self.o1=self.log(l);return w
 def tab2(self):
  w,l=self.page('Explore OpenSSL named curves over prime and binary fields. All seven tabs support both types where explicit parameters are available.');f=self.form(l,'Named curves');self.curves=QComboBox();f.addRow('Curve:',self.curves)
  self.btn(l,'Refresh OpenSSL Curve List',self.discover);self.btn(l,'Inspect and Validate Parameters',self.inspect);self.o2=self.log(l);return w
 def discover(self):
  found={}
  for line in self.run('ecparam','-list_curves').splitlines():
   m=re.match(r'^\s*(\S+)\s*:\s*(.*)$',line)
   if m:found[m.group(1)]=m.group(2)
  if not found:raise ValueError('No curves discovered')
  old=self.curves.currentText();self.curves.clear()
  for name in [n for n in PREFERRED if n in found]+sorted(set(found)-set(PREFERRED)):self.curves.addItem(name,found[name])
  self.curves.setCurrentText(old if old in found else ('prime256v1' if 'prime256v1' in found else next(iter(found))))
  self.o2.setPlainText(f'{len(found)} OpenSSL named curves discovered.\nSelect a curve and inspect it.\nPrime-field and binary-field curves: Tabs 2–7.\nLegacy curves may be disabled by provider policy.')
 def inspect(self):
  C=self.params();N=C.n*C.h;q=C.q
  eq='y² + xy = x³ + ax² + b' if C.kind=='binary' else 'y² = x³ + ax + b'
  modulus_label='Reduction polynomial f(t)' if C.kind=='binary' else 'Prime modulus p'
  non_singular=(C.b!=0) if C.kind=='binary' else ((4*C.a**3+27*C.b**2)%C.modulus!=0)
  self.o2.setPlainText(f'Curve: {C.name}\nField: {"GF(2^"+str(C.degree)+")" if C.kind=="binary" else "GF(p)"}\nEquation: {eq}\n{modulus_label}:\n{pretty(C.modulus)}\na: 0x{C.a:x}\nb: 0x{C.b:x}\n\nGenerator G:\n{self.showpoint(C.G)}\n\nSubgroup order n: {C.n}\nCofactor h: {C.h}\nFull group order N=n*h: {N}\nHasse bound: {(N-q-1)**2<=4*q}\nNonsingular: {non_singular}\nG on curve: {on_curve(C.G,C)}\n[n]G=O: {mul(C.n,C.G,C) is None}\n\nField arithmetic: {"binary polynomial XOR / reduction" if C.kind=="binary" else "modular prime arithmetic"}')
 def tab3(self):
  w,l=self.page('Compare the full elliptic-curve group and the subgroup generated by G, for prime and binary fields.');f=self.form(l,'Point and group');self.group_point=self.entry(f,'SEC1 point HEX or O:');self.btn(l,'Use generator G',lambda:self.group_point.setText(encode(self.params().G,self.params()).hex()));self.btn(l,'Check Group / Subgroup Membership',self.groupcheck);self.o3=self.log(l);return w
 def groupcheck(self):
  C=self.params();P=self.point(self.group_point.text())
  self.o3.setPlainText(f'Curve: {C.name} ({C.kind})\nFull group order N={C.n*C.h}\nGenerator subgroup order n={C.n}\nCofactor h={C.h}\nPoint on curve: {on_curve(P,C)}\n[n]P=O: {mul(C.n,P,C) is None}\nPoint:\n{self.showpoint(P)}\n\nFor prime n, [n]P=O is a subgroup membership test. For composite n it checks n-torsion only.')
 def tab4(self):
  w,l=self.page('Group operations on prime-field or binary-field curves: P+Q, P−Q, −P, 2P and identity.');f=self.form(l,'Operands');self.P=self.entry(f,'P:');self.Q=self.entry(f,'Q:');self.op=self.combo(f,'Operation:',['P + Q','P - Q','-P','2P','P + O','P + (-P)']);self.btn(l,'Set P = G',lambda:self.P.setText(encode(self.params().G,self.params()).hex()));self.btn(l,'Set Q = G',lambda:self.Q.setText(encode(self.params().G,self.params()).hex()));self.btn(l,'Calculate',self.arithmetic);self.o4=self.log(l);return w
 def arithmetic(self):
  C=self.params();P=self.point(self.P.text());mode=self.op.currentText();Q=self.point(self.Q.text()) if mode in ('P + Q','P - Q') else None
  R={'P + Q':lambda:add(P,Q,C),'P - Q':lambda:add(P,neg(Q,C),C),'-P':lambda:neg(P,C),'2P':lambda:add(P,P,C),'P + O':lambda:P,'P + (-P)':lambda:add(P,neg(P,C),C)}[mode]()
  law=('Binary: -(x,y)=(x,x+y); addition λ=(y1+y2)/(x1+x2); doubling λ=x+y/x.\nFor P!=Q: x3=λ²+λ+x1+x2+a, y3=λ(x1+x3)+x3+y1.\nFor doubling: x3=λ²+λ+a, y3=x1²+(λ+1)x3.' if C.kind=='binary' else 'Prime: -(x,y)=(x,-y); addition λ=(y2-y1)/(x2-x1); doubling λ=(3x1²+a)/(2y1).\nx3=λ²-x1-x2; y3=λ(x1-x3)-y1 (mod p).')
  self.o4.setPlainText(f'Curve: {C.name}\nOperation: {mode}\nResult:\n{self.showpoint(R)}\n\n{law}')
 def tab5(self):
  w,l=self.page('Double-and-add scalar multiplication for both field types. Try k=0, n, n+1 or negative k.');f=self.form(l,'Scalar multiplication');self.scalar_point=self.entry(f,'P (SEC1 HEX or O):');self.scalar=self.entry(f,'k (decimal or 0xHEX):','2');self.btn(l,'Set P = G',lambda:self.scalar_point.setText(encode(self.params().G,self.params()).hex()));self.btn(l,'Compute [k]P',self.scalarcalc);self.o5=self.log(l);return w
 def scalarcalc(self):
  C=self.params();P=self.point(self.scalar_point.text());k=int(self.scalar.text(),0) if self.scalar.text().strip().lower().startswith('0x') else int(self.scalar.text());R=mul(k,P,C)
  self.o5.setPlainText(f'Curve: {C.name}\nk={k}\n[k]P:\n{self.showpoint(R)}\n[n]G=O: {mul(C.n,C.G,C) is None}\nDouble-and-add: O(log |k|) group operations.')
 def tab6(self):
  w,l=self.page('Reversible educational encoding for prime and binary curves. x=01 || length(2) || payload(padded) || counter(2). Not cryptographic hash-to-curve.');f=self.form(l,'Plaintext');self.msg_fmt=self.combo(f,'Input:',['UTF-8 text','HEX bytes']);self.message=self.entry(f,'Message:','Hello ECC');self.btn(l,'Encode Message to Curve Point',self.mapmsg);self.btn(l,'Copy Encoded Point to Arithmetic P',self.copy_encoded_to_arithmetic);self.o6=self.log(l);return w
 def copy_encoded_to_arithmetic(self):
  if self.last_point is None:raise ValueError('Encode a message first')
  if self.last_curve!=self.curve_name():raise ValueError('Choose the curve used to encode this point: '+self.last_curve)
  self.P.setText(encode(self.last_point,self.params()).hex());self.tabs.setCurrentIndex(3)
 def mapmsg(self):
  raw=self.message.text().encode('utf-8') if self.msg_fmt.currentIndex()==0 else hbytes(self.message.text());C=self.params();P,counter=encode_message_point(raw,C);decoded,_=decode_message_point(P,C)
  if decoded!=raw:raise ValueError('Round-trip mismatch')
  self.last_point=P;self.last_bytes=raw;self.last_curve=C.name
  self.o6.setPlainText(f'Curve: {C.name} ({C.kind})\nInput length: {len(raw)} bytes; capacity: {point_payload_capacity(C)} bytes\nMessage HEX: {raw.hex()}\nCounter: {counter}\nPoint M:\n{self.showpoint(P)}\n[n]M=O: {mul(C.n,P,C) is None}\nDecode round trip: PASS\n\nEducational reversible mapping to E(F); point may lie outside <G> when h>1. Not suitable for secure encryption or hash-to-curve.')
 def tab7(self):
  w,l=self.page('Decode a point from Tab 6 back to plaintext for both prime and binary curves.');f=self.form(l,'Encoded point');self.decode_point=self.entry(f,'SEC1 point HEX:');self.btn(l,'Use Point from Tab 6',self.transfer);self.btn(l,'Decode Point to Plaintext',self.unmap);self.o7=self.log(l);return w
 def transfer(self):
  if self.last_point is None:raise ValueError('Encode a message first')
  if self.last_curve!=self.curve_name():raise ValueError('Choose the curve used to encode this point: '+self.last_curve)
  self.decode_point.setText(encode(self.last_point,self.params()).hex())
 def unmap(self):
  C=self.params();P=self.point(self.decode_point.text());raw,counter=decode_message_point(P,C)
  try:s=raw.decode('utf-8')
  except UnicodeDecodeError:s='(not valid UTF-8)'
  self.o7.setPlainText(f'Curve: {C.name}\nPoint:\n{self.showpoint(P)}\nCounter: {counter}\nRecovered bytes: {len(raw)}\nPlaintext HEX: {raw.hex()}\nPlaintext UTF-8: {s}')

def main():
 app=QApplication(sys.argv);app.setFont(QFont('Arial',14));w=Window();w.show();sys.exit(app.exec())
if __name__=='__main__':main()
