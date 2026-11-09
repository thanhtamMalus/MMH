"""Week 08 — Textbook EC ElGamal (OpenSSL + PyQt6).
Five-tab GUI modeled on Week07 ElGamal v3. Educational point messages only.
Dependencies: pip install PyQt6 cryptography. OpenSSL CLI required.
"""
from __future__ import annotations
import re, secrets, shutil, subprocess, sys
from pathlib import Path
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QApplication,QMainWindow,QWidget,QTabWidget,QVBoxLayout,QHBoxLayout,
    QFormLayout,QGroupBox,QLabel,QLineEdit,QPushButton,QTextEdit,QComboBox,QFileDialog,
    QMessageBox,QCheckBox)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

OUT=Path.cwd()/"week08_ecc_elgamal_output";OUT.mkdir(parents=True,exist_ok=True)
PREFERRED=['prime256v1','secp384r1','secp521r1','secp256k1','secp224r1','secp192r1',
           'brainpoolP256r1','brainpoolP384r1','brainpoolP512r1','SM2',
           'sect163r2','sect233r1','sect283r1','sect409r1','sect571r1']
KEY_FORMATS=['PEM (.pem)','DER binary (.bin)','DER hex (.hex)']
DATA_FORMATS=['Hex text (.hex)','Binary (.bin)']

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

def add(P,Q,p,a):
    if P is None:return Q
    if Q is None:return P
    x,y=P;u,v=Q
    if x==u and (y+v)%p==0:return None
    if P==Q:
        if y%p==0:return None
        slope=(3*x*x+a)*pow(2*y,-1,p)%p
    else:slope=(v-y)*pow((u-x)%p,-1,p)%p
    rx=(slope*slope-x-u)%p
    return rx,(slope*(x-rx)-y)%p

def mul(k,P,p,a):
    if k<0:raise ValueError('Negative scalar')
    R=None
    while k:
        if k&1:R=add(R,P,p,a)
        P=add(P,P,p,a);k>>=1
    return R

def on_curve(P,p,a,b):
    return P is not None and 0<=P[0]<p and 0<=P[1]<p and (P[1]**2-P[0]**3-a*P[0]-b)%p==0

def encode(P,p,compressed=False):
    if P is None:raise ValueError('Cannot serialize point at infinity')
    L=(p.bit_length()+7)//8
    return (bytes([2+(P[1]&1)])+P[0].to_bytes(L,'big') if compressed else
            b'\x04'+P[0].to_bytes(L,'big')+P[1].to_bytes(L,'big'))

def decode(data,p,a,b):
    # OpenSSL-backed cryptography SEC1 decoder validates compressed and uncompressed encodings.
    # Use manual uncompressed parsing for generic explicit prime-field curves not exposed by cryptography.
    L=(p.bit_length()+7)//8
    if len(data)==1+2*L and data[0]==4:
        P=(int.from_bytes(data[1:1+L],'big'),int.from_bytes(data[1+L:],'big'))
    elif len(data)==1+L and data[0] in (2,3):
        x=int.from_bytes(data[1:],'big')
        if x>=p:raise ValueError('Point x outside field')
        rhs=(pow(x,3,p)+a*x+b)%p
        if rhs==0:y=0
        else:
            if pow(rhs,(p-1)//2,p)!=1:raise ValueError('Compressed point has no square root')
            if p%4==3:y=pow(rhs,(p+1)//4,p)
            else:
                q=p-1;s=0
                while q%2==0:q//=2;s+=1
                z=2
                while pow(z,(p-1)//2,p)!=p-1:z+=1
                c=pow(z,q,p);y=pow(rhs,(q+1)//2,p);t=pow(rhs,q,p);m=s
                while t!=1:
                    i=1;v=t*t%p
                    while i<m and v!=1:v=v*v%p;i+=1
                    if i==m:raise ValueError('Tonelli–Shanks failed')
                    u=pow(c,1<<(m-i-1),p);y=y*u%p;t=t*u*u%p;c=u*u%p;m=i
        if y%2!=data[0]%2:y=(-y)%p
        P=(x,y)
    else:raise ValueError('Expected SEC1 compressed or uncompressed EC point')
    if not on_curve(P,p,a,b):raise ValueError('Point fails curve equation')
    return P

# Educational reversible byte-to-point encoding, NOT a cryptographic hash-to-curve.
# Fixed x layout: 0x01 || length(2) || payload(padded) || counter(2).
# One short message per point; the counter searches for a valid point in <G>.
POINT_MAGIC = 0x01

def point_payload_capacity(p):
    return (p.bit_length()+7)//8 - 5

def encode_message_point(raw, params):
    p,a,b,G,n,h=params
    cap=point_payload_capacity(p)
    if cap < 1 or len(raw)>cap:
        raise ValueError(f'Plaintext length {len(raw)} exceeds {cap} bytes for this curve. Use a shorter message or ECIES for general data.')
    width=(p.bit_length()+7)//8
    prefix=bytes([POINT_MAGIC])+len(raw).to_bytes(2,'big')+raw.ljust(cap,b'\x00')
    for counter in range(65536):
        x=int.from_bytes(prefix+counter.to_bytes(2,'big'),'big')
        if x>=p:continue
        rhs=(pow(x,3,p)+a*x+b)%p
        if rhs==0:
            y=0
        elif pow(rhs,(p-1)//2,p)!=1:
            continue
        elif p%4==3:
            y=pow(rhs,(p+1)//4,p)
        else:
            # Reuse the existing SEC1 compressed-point square-root routine.
            try:
                return_point=decode(bytes([2])+x.to_bytes(width,'big'),p,a,b)
                y=return_point[1]
            except ValueError:
                continue
        if y&1:y=p-y
        P=(x,y)
        if mul(n,P,p,a) is None:
            return P,counter
    raise ValueError('No subgroup point found in 65536 attempts; try a different plaintext')

def decode_message_point(P,params):
    p,a,b,G,n,h=params
    if not on_curve(P,p,a,b) or mul(n,P,p,a) is not None:
        raise ValueError('Invalid point or point outside selected subgroup')
    width=(p.bit_length()+7)//8
    buf=P[0].to_bytes(width,'big')
    cap=point_payload_capacity(p)
    if buf[0]!=POINT_MAGIC:
        raise ValueError('Point is not encoded with the Week 8 reversible plaintext format')
    length=int.from_bytes(buf[1:3],'big')
    if length>cap:raise ValueError('Invalid embedded plaintext length')
    padded=buf[3:3+cap]
    if any(padded[length:]):raise ValueError('Invalid plaintext padding')
    counter=int.from_bytes(buf[-2:],'big')
    return padded[:length],counter

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__();self.setWindowTitle('Week 08 — EC ElGamal over OpenSSL Named Curves');self.resize(1240,880)
        self.ssl=shutil.which('openssl') or 'openssl';self.curve='prime256v1'
        self.params=None;self.private=None;self.public=None;self.enc_public=None;self.dec_private=None
        self.C1=None;self.C2=None;self.ct_curve=None;self.recovered=None;self.last_message=None
        self.priv_file=OUT/'recipient_private.pem';self.pub_file=OUT/'recipient_public.pem'
        self.tabs=QTabWidget();self.setCentralWidget(self.tabs)
        for label,fn in [('1. OpenSSL Settings',self.tab1),('2. EC Curve Parameters',self.tab2),
                         ('3. EC ElGamal Key Pair',self.tab3),('4. Encryption',self.tab4),
                         ('5. Decryption',self.tab5),('6. Encode Plaintext',self.tab6),('7. Decode Point',self.tab7)]:self.tabs.addTab(fn(),label)
        self.safe(self.discover)

    def safe(self,fn):
        try:fn()
        except Exception as exc:QMessageBox.critical(self,'Error',str(exc))
    def run(self,*args):
        self.ssl=self.ssl_edit.text().strip() or 'openssl'
        cp=subprocess.run([self.ssl,*map(str,args)],capture_output=True,check=False)
        if cp.returncode:raise RuntimeError(f'OpenSSL failed: {cp.stderr.decode(errors="replace")}')
        return cp.stdout
    def text(self,*args):return self.run(*args).decode(errors='replace')
    def mono(self,widget):
        f=QFont('Consolas');f.setStyleHint(QFont.StyleHint.Monospace);widget.setFont(f)
    def page(self,description):
        w=QWidget();layout=QVBoxLayout(w);label=QLabel(description);label.setWordWrap(True);layout.addWidget(label)
        return w,layout
    def group(self,layout,title):
        box=QGroupBox(title);form=QFormLayout(box);layout.addWidget(box);return form
    def button(self,layout,title,fn):
        b=QPushButton(title);b.clicked.connect(lambda:self.safe(fn));layout.addWidget(b);return b
    def output(self,layout):
        o=QTextEdit();o.setReadOnly(True);self.mono(o);layout.addWidget(o);return o
    def open_path(self,title):return QFileDialog.getOpenFileName(self,title,str(OUT),'All files (*)')[0]
    def save_path(self,title,name):return QFileDialog.getSaveFileName(self,title,str(OUT/name),'All files (*)')[0]
    def fmt_combo(self,values):
        c=QComboBox();c.addItems(values);return c

    # Tab 1
    def tab1(self):
        w,l=self.page('<b>Goal:</b> configure OpenSSL. OpenSSL supplies named curves and key generation; Python performs textbook EC point-group ElGamal.')
        f=self.group(l,'OpenSSL Configuration');self.ssl_edit=QLineEdit(self.ssl)
        row=QHBoxLayout();row.addWidget(self.ssl_edit)
        b=QPushButton('Browse...');b.clicked.connect(lambda:self.safe(self.browse_ssl));row.addWidget(b)
        f.addRow('OpenSSL executable:',row);self.button(l,'Test OpenSSL',self.test_ssl)
        self.o1=self.output(l);return w
    def browse_ssl(self):
        p=self.open_path('Select OpenSSL executable')
        if p:self.ssl_edit.setText(p)
    def test_ssl(self):
        self.o1.setPlainText('=== OPENSSL ===\n'+self.text('version','-a')+'\n=== PROVIDERS ===\n'+self.text('list','-providers')+
            '\nOpenSSL has no generic EC ElGamal CLI. OpenSSL handles EC parameters and keys; Python computes the group equations.')

    # Tab 2
    def tab2(self):
        w,l=self.page('<b>Goal:</b> inspect full elliptic-curve parameters: field, equation, generator G, order n, and cofactor h. Curves are discovered from the configured OpenSSL installation.')
        f=self.group(l,'Public EC Domain Parameters')
        self.curve_combo=QComboBox();f.addRow('Named curve:',self.curve_combo)
        self.button(l,'Refresh Curve List from OpenSSL',self.discover)
        self.button(l,'Inspect Selected Curve: p, a, b, G, n, h',self.inspect)
        self.o2=self.output(l);return w
    def discover(self):
        found={}
        for line in self.text('ecparam','-list_curves').splitlines():
            m=re.match(r'^\s*(\S+)\s*:\s*(.+)$',line)
            if m:found[m.group(1)]=m.group(2)
        if not found:raise RuntimeError('No curves reported by OpenSSL')
        previous=self.curve_combo.currentText();self.curve_combo.clear()
        for name in [x for x in PREFERRED if x in found]+sorted(set(found)-set(PREFERRED)):
            self.curve_combo.addItem(name,found[name])
        target=previous if previous in found else ('prime256v1' if 'prime256v1' in found else next(iter(found)))
        self.curve_combo.setCurrentText(target)
        self.o2.setPlainText(f'{len(found)} named curves discovered. Legacy and binary-field curves are shown for academic comparison.\n'
            'Point ElGamal supports prime-field short-Weierstrass curves with compatible EC keys.\n'
            'X25519/X448 are not Weierstrass EC ElGamal curves.')
    def inspect(self):
        name=self.curve_combo.currentText()
        txt=self.text('ecparam','-name',name,'-param_enc','explicit','-text','-noout')
        self.o2.setPlainText(f'Named curve: {name}\n\n'+txt+'\nNOTE: A curve being listed does not guarantee key-generation support or modern security.')
    def params_for(self,name):
        txt=self.text('ecparam','-name',name,'-param_enc','explicit','-text','-noout')
        if not re.search(r'Field Type:\s*prime-field',txt,re.I):
            raise ValueError('Only prime-field short-Weierstrass curves are supported for point ElGamal; binary-field curves are inspection-only.')
        def val(header):
            m=re.search(r'^'+re.escape(header)+r'[ \t]*:[ \t]*(.*)$',txt,re.M|re.I)
            if not m:raise ValueError('OpenSSL parameter missing: '+header)
            inline=m.group(1).strip()
            if inline.startswith('0x'):return int(inline,16)
            if re.match(r'^\d+(?:\s|$)',inline):return int(inline.split()[0])
            octets=[]
            for line in txt[m.end():].splitlines():
                s=line.strip()
                if re.fullmatch(r'(?:[0-9a-fA-F]{2}:)*[0-9a-fA-F]{2}:?',s):
                    octets.extend(re.findall(r'[0-9a-fA-F]{2}',s))
                elif octets:break
            if not octets:raise ValueError('Cannot parse '+header)
            return int(''.join(octets),16)
        p=val('Prime');a=val('A')%p;b=val('B')%p;n=val('Order');h=val('Cofactor')
        m=re.search(r'^Generator\s*\([^\n]*\)\s*:\s*$',txt,re.M|re.I)
        if not m:raise ValueError('OpenSSL generator section not found')
        octets=[]
        for line in txt[m.end():].splitlines():
            s=line.strip()
            if not s and not octets:
                continue  # OpenSSL places a newline after the Generator heading.
            if re.fullmatch(r'(?:[0-9a-fA-F]{2}:)*[0-9a-fA-F]{2}:?',s):
                octets.extend(re.findall(r'[0-9a-fA-F]{2}',s))
            elif octets:
                break
            elif s:
                raise ValueError('Unexpected OpenSSL generator encoding: '+s)
        if not octets:
            raise ValueError('OpenSSL generator section contains no SEC1 point bytes')
        G=decode(bytes.fromhex(''.join(octets)),p,a,b)
        if (4*a**3+27*b*b)%p==0 or mul(n,G,p,a) is not None:
            raise ValueError('Curve discriminant or base-point order validation failed')
        return (p,a,b,G,n,h)
    def selected_params(self):
        name=self.curve_combo.currentText()
        if self.params is None or self.curve!=name:
            self.params=self.params_for(name);self.curve=name
        return self.params
    def detailed_params(self):
        p,a,b,G,n,h=self.selected_params()
        return (f'Curve: {self.curve}\nField: F_p, p bits={p.bit_length()}\n'
                f'p (HEX):\n{pretty(p)}\na (HEX):\n{pretty(a)}\nb (HEX):\n{pretty(b)}\n'
                f'G (SEC1 HEX):\n{encode(G,p).hex()}\n'
                f'n (HEX):\n{pretty(n)}\nh={h}; #E(F_p)=n*h\n')

    # Tab 3
    def tab3(self):
        w,l=self.page('<b>Goal:</b> generate a recipient EC ElGamal key pair: private scalar d and public point Q=[d]G. Save private and public keys independently.')
        self.button(l,'Generate EC ElGamal Key Pair',self.keygen)
        self.show_params=QCheckBox('Show detailed p, a, b, G, n, h with key details');l.addWidget(self.show_params)
        f=self.group(l,'Save Private Key');self.priv_fmt=self.fmt_combo(KEY_FORMATS);f.addRow('Format:',self.priv_fmt)
        b=QPushButton('Save Private Key As...');b.clicked.connect(lambda:self.safe(lambda:self.save_key(True)));f.addRow(b)
        f=self.group(l,'Save Public Key');self.pub_fmt=self.fmt_combo(KEY_FORMATS);f.addRow('Format:',self.pub_fmt)
        b=QPushButton('Save Public Key As...');b.clicked.connect(lambda:self.safe(lambda:self.save_key(False)));f.addRow(b)
        self.o3=self.output(l);return w
    def keygen(self):
        p,a,b,G,n,h=self.selected_params()
        self.run('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:'+self.curve,'-out',self.priv_file)
        self.run('pkey','-in',self.priv_file,'-pubout','-out',self.pub_file)
        self.private=serialization.load_pem_private_key(self.priv_file.read_bytes(),password=None)
        if not isinstance(self.private,ec.EllipticCurvePrivateKey):raise ValueError('Generated key is not EC')
        self.public=self.private.public_key()
        d=self.private.private_numbers().private_value;q=self.public.public_numbers();Q=(q.x,q.y)
        if Q!=mul(d,G,p,a):raise ValueError('OpenSSL EC public key != [d]G')
        self.o3.setPlainText(f'Named curve: {self.curve}\n'+(self.detailed_params()+'\n' if self.show_params.isChecked() else '')+
            '=== EC ELGAMAL KEY RELATION ===\nQ=[d]G\n'
            f'd (HEX, secret):\n{pretty(d)}\nQ.x (HEX):\n{pretty(Q[0])}\nQ.y (HEX):\n{pretty(Q[1])}\n'
            f'Q (SEC1 HEX):\n{encode(Q,p).hex()}\nConsistency check: TRUE\n\n'
            f'Private key: {self.priv_file}\nPublic key: {self.pub_file}\nKeep d secret.')
    def key_bytes(self,key,private,fmt):
        encoding=serialization.Encoding.PEM if fmt=='PEM (.pem)' else serialization.Encoding.DER
        if private:return key.private_bytes(encoding,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        return key.public_bytes(encoding,serialization.PublicFormat.SubjectPublicKeyInfo)
    def save_key(self,private):
        key=self.private if private else self.public
        if key is None:raise ValueError('Generate key pair first')
        fmt=self.priv_fmt.currentText() if private else self.pub_fmt.currentText()
        ext='.pem' if fmt.startswith('PEM') else '.bin' if 'binary' in fmt else '.hex'
        path=self.save_path('Save EC '+('private' if private else 'public')+' key','ec_elgamal_'+('private' if private else 'public')+ext)
        if not path:return
        data=self.key_bytes(key,private,fmt)
        if ext=='.hex':Path(path).write_text(data.hex()+'\n',encoding='utf-8')
        else:Path(path).write_bytes(data)
        self.o3.append(f'\nSaved {"PRIVATE" if private else "PUBLIC"} key: {path} ({fmt})')
    def load_key(self,private,fmt):
        path=self.open_path('Load recipient '+('private' if private else 'public')+' EC key')
        if not path:return None,None
        data=Path(path).read_bytes()
        if fmt=='DER hex (.hex)':data=hbytes(data.decode('utf-8'))
        if private:
            key=(serialization.load_pem_private_key(data,password=None) if fmt.startswith('PEM') else
                 serialization.load_der_private_key(data,password=None))
            if not isinstance(key,ec.EllipticCurvePrivateKey):raise ValueError('Not an EC private key')
        else:
            key=(serialization.load_pem_public_key(data) if fmt.startswith('PEM') else
                 serialization.load_der_public_key(data))
            if not isinstance(key,ec.EllipticCurvePublicKey):raise ValueError('Not an EC public key')
        return key,path
    def validate_key(self,key):
        p,a,b,G,n,h=self.selected_params()
        aliases={'prime256v1':'secp256r1'}
        if key.curve.name.lower()!=aliases.get(self.curve,self.curve).lower():
            raise ValueError(f'Key curve {key.curve.name} differs from selected {self.curve}')
        q=key.public_key().public_numbers() if isinstance(key,ec.EllipticCurvePrivateKey) else key.public_numbers()
        Q=(q.x,q.y)
        if not on_curve(Q,p,a,b) or mul(n,Q,p,a) is not None:raise ValueError('Invalid EC public key/subgroup')
        return Q

    # Tab 4
    def tab4(self):
        w,l=self.page('<b>EC ElGamal encryption:</b> load recipient public key; input a curve point M (SEC1 HEX). Compute C1=[k]G and C2=M+[k]Q with fresh k. Arbitrary UTF-8 is NOT directly a curve point.')
        f=self.group(l,'Recipient Public Key');self.enc_pub_fmt=self.fmt_combo(KEY_FORMATS);f.addRow('Format:',self.enc_pub_fmt)
        self.enc_pub_path=QLineEdit();self.enc_pub_path.setReadOnly(True);f.addRow('Loaded file:',self.enc_pub_path)
        b=QPushButton('Load Recipient Public Key');b.clicked.connect(lambda:self.safe(self.load_enc_public));f.addRow(b)
        f=self.group(l,'Message Point M');self.msg_fmt=self.fmt_combo(['SEC1 uncompressed HEX','SEC1 compressed HEX']);f.addRow('Point encoding:',self.msg_fmt)
        self.msg=QLineEdit();self.msg.setPlaceholderText('04... or 02... / 03... SEC1 point');f.addRow('Point M:',self.msg)
        b=QPushButton('Use Base Point G as Message');b.clicked.connect(lambda:self.safe(self.use_G));f.addRow(b)
        b=QPushButton('Encrypt with Fresh Random k');b.clicked.connect(lambda:self.safe(self.encrypt));f.addRow(b)
        f=self.group(l,'Save Ciphertext (C1, C2)');self.ct_fmt=self.fmt_combo(DATA_FORMATS);f.addRow('Format:',self.ct_fmt)
        b=QPushButton('Save Ciphertext');b.clicked.connect(lambda:self.safe(self.save_ct));f.addRow(b)
        self.o4=self.output(l);return w
    def load_enc_public(self):
        key,path=self.load_key(False,self.enc_pub_fmt.currentText())
        if key is None:return
        Q=self.validate_key(key);self.enc_public=key;self.enc_pub_path.setText(path)
        self.o4.setPlainText(f'PUBLIC KEY LOADED\nSource: {path}\nCurve: {self.curve}\nQ.x:\n{pretty(Q[0])}\nQ.y:\n{pretty(Q[1])}')
    def use_G(self):
        p,a,b,G,n,h=self.selected_params()
        self.msg.setText(encode(G,p,self.msg_fmt.currentIndex()==1).hex())
    def encrypt(self):
        if self.enc_public is None:raise ValueError('Load recipient public key first')
        p,a,b,G,n,h=self.selected_params();Q=self.validate_key(self.enc_public)
        M=decode(hbytes(self.msg.text()),p,a,b)
        if mul(n,M,p,a) is not None:raise ValueError('M is not in the subgroup generated by G')
        k=secrets.randbelow(n-1)+1;C1=mul(k,G,p,a);C2=add(M,mul(k,Q,p,a),p,a)
        if C2 is None:raise ValueError('C2 is point at infinity; retry with new k')
        self.C1,self.C2,self.ct_curve,self.last_message=C1,C2,self.curve,M
        self.o4.append(f'\n=== EC ELGAMAL ENCRYPTION ===\nCurve: {self.curve}\n'
            f'M (SEC1 HEX): {encode(M,p).hex()}\nEphemeral k (TEACHING ONLY):\n{pretty(k)}\n'
            f'C1=[k]G\n x={pretty(C1[0])}\n y={pretty(C1[1])}\n'
            f'C2=M+[k]Q\n x={pretty(C2[0])}\n y={pretty(C2[1])}\n'
            f'C1 SEC1 HEX:\n{encode(C1,p).hex()}\nC2 SEC1 HEX:\n{encode(C2,p).hex()}\n'
            'This textbook scheme is malleable and not authenticated.')
    def pack_ct(self):
        if self.C1 is None or self.C2 is None:raise ValueError('Encrypt first')
        if self.ct_curve!=self.curve_combo.currentText():raise ValueError('Curve changed since encryption')
        p,*_=self.selected_params();c1=encode(self.C1,p);c2=encode(self.C2,p)
        name=self.curve.encode('ascii')
        if len(name)>255:raise ValueError('Curve name too long')
        return b'ECELG1'+bytes([len(name)])+name+len(c1).to_bytes(2,'big')+c1+len(c2).to_bytes(2,'big')+c2
    def save_ct(self):
        fmt=self.ct_fmt.currentText();ext='.bin' if fmt=='Binary (.bin)' else '.hex'
        data=self.pack_ct();path=self.save_path('Save EC ElGamal ciphertext','ec_elgamal_ciphertext'+ext)
        if path:write_data(Path(path),data,fmt);self.o4.append(f'\nCiphertext saved: {path}')

    # Tab 5
    def tab5(self):
        w,l=self.page('<b>EC ElGamal decryption:</b> load recipient private key and ciphertext independently, then recover M=C2-[d]C1. The recovered plaintext is an EC point.')
        f=self.group(l,'Recipient Private Key');self.dec_priv_fmt=self.fmt_combo(KEY_FORMATS);f.addRow('Format:',self.dec_priv_fmt)
        self.dec_priv_path=QLineEdit();self.dec_priv_path.setReadOnly(True);f.addRow('Loaded file:',self.dec_priv_path)
        b=QPushButton('Load Private Key');b.clicked.connect(lambda:self.safe(self.load_dec_private));f.addRow(b)
        f=self.group(l,'Ciphertext');self.dec_ct_fmt=self.fmt_combo(DATA_FORMATS);f.addRow('Format:',self.dec_ct_fmt)
        self.dec_ct_path=QLineEdit();self.dec_ct_path.setReadOnly(True);f.addRow('Loaded file:',self.dec_ct_path)
        b=QPushButton('Load Ciphertext');b.clicked.connect(lambda:self.safe(self.load_ct));f.addRow(b)
        b=QPushButton('Decrypt');b.clicked.connect(lambda:self.safe(self.decrypt));f.addRow(b)
        f=self.group(l,'Recovered Message Point M');self.plain_fmt=self.fmt_combo(DATA_FORMATS);f.addRow('Format:',self.plain_fmt)
        b=QPushButton('Save Recovered Point');b.clicked.connect(lambda:self.safe(self.save_plain));f.addRow(b)
        self.o5=self.output(l);return w
    def load_dec_private(self):
        key,path=self.load_key(True,self.dec_priv_fmt.currentText())
        if key is None:return
        self.validate_key(key);self.dec_private=key;self.dec_priv_path.setText(path)
        self.o5.setPlainText(f'PRIVATE KEY LOADED\nSource: {path}\nCurve: {self.curve}\nPrivate d (TEACHING ONLY):\n{pretty(key.private_numbers().private_value)}')
    def load_ct(self):
        fmt=self.dec_ct_fmt.currentText();path=self.open_path('Load EC ElGamal ciphertext')
        if not path:return
        data=read_data(Path(path),fmt)
        if not data.startswith(b'ECELG1') or len(data)<10:raise ValueError('Invalid EC ElGamal ciphertext header')
        i=6;name_len=data[i];i+=1
        if i+name_len+4>len(data):raise ValueError('Truncated ciphertext')
        name=data[i:i+name_len].decode('ascii');i+=name_len
        if name!=self.curve_combo.currentText():raise ValueError(f'Ciphertext curve {name} != selected {self.curve_combo.currentText()}')
        p,a,b,G,n,h=self.selected_params()
        n1=int.from_bytes(data[i:i+2],'big');i+=2
        if n1==0 or i+n1+2>len(data):raise ValueError('Malformed C1 length')
        c1=data[i:i+n1];i+=n1;n2=int.from_bytes(data[i:i+2],'big');i+=2
        if n2==0 or i+n2!=len(data):raise ValueError('Malformed C2 length')
        c2=data[i:i+n2]
        C1=decode(c1,p,a,b);C2=decode(c2,p,a,b)
        if mul(n,C1,p,a) is not None or mul(n,C2,p,a) is not None:raise ValueError('Ciphertext points outside base-point subgroup')
        self.C1,self.C2,self.ct_curve=C1,C2,name;self.recovered=None
        self.dec_ct_path.setText(path)
        self.o5.append(f'\nCIPHERTEXT LOADED\nSource: {path}\nCurve: {name}\nC1: {c1.hex()}\nC2: {c2.hex()}')
    def decrypt(self):
        if self.dec_private is None or self.C1 is None or self.C2 is None:raise ValueError('Load private key and ciphertext first')
        if self.ct_curve!=self.curve_combo.currentText():raise ValueError('Ciphertext curve differs from selected curve')
        p,a,b,G,n,h=self.selected_params();self.validate_key(self.dec_private)
        d=self.dec_private.private_numbers().private_value
        S=mul(d,self.C1,p,a)
        if S is None:raise ValueError('Invalid shared point')
        M=add(self.C2,(S[0],(-S[1])%p),p,a)
        if M is None:raise ValueError('Recovered point at infinity; not representable as SEC1')
        self.recovered=M
        self.o5.append(f'\n=== EC ELGAMAL DECRYPTION ===\nS=[d]C1\nM=C2-S\n'
            f'M.x (HEX):\n{pretty(M[0])}\nM.y (HEX):\n{pretty(M[1])}\n'
            f'M (SEC1 HEX):\n{encode(M,p).hex()}\n'
            f'Matches last in-memory message: {M==self.last_message if self.last_message is not None else "not available"}')
    def save_plain(self):
        if self.recovered is None:raise ValueError('Decrypt first')
        fmt=self.plain_fmt.currentText();ext='.bin' if fmt=='Binary (.bin)' else '.hex'
        path=self.save_path('Save recovered EC point','ec_elgamal_recovered_point'+ext)
        if path:write_data(Path(path),encode(self.recovered,self.selected_params()[0]),fmt);self.o5.append(f'\nRecovered point saved: {path}')

    # Tab 6: reversible educational plaintext -> EC point.
    def tab6(self):
        w,l=self.page('<b>Reversible teaching encoding:</b> map a SHORT UTF-8 or HEX message to an EC point by trying candidate x coordinates. This is not hash-to-curve or production encryption. Select the same curve as Tabs 2–5.')
        f=self.group(l,'Plaintext input')
        self.encode_fmt=self.fmt_combo(['Text (UTF-8)','Hex bytes']);f.addRow('Input format:',self.encode_fmt)
        self.encode_text=QLineEdit('Hello ECC');f.addRow('Plaintext:',self.encode_text)
        b=QPushButton('Encode Plaintext to Curve Point M');b.clicked.connect(lambda:self.safe(self.do_encode_message));f.addRow(b)
        b=QPushButton('Use Encoded Point in Tab 4 (Encryption)');b.clicked.connect(lambda:self.safe(self.send_encoded_to_encrypt));f.addRow(b)
        f=self.group(l,'Save Encoded SEC1 Point')
        self.encode_save_fmt=self.fmt_combo(DATA_FORMATS);f.addRow('Format:',self.encode_save_fmt)
        b=QPushButton('Save Encoded Point');b.clicked.connect(lambda:self.safe(self.save_encoded_point));f.addRow(b)
        self.o6=self.output(l);self.encoded_point=None;self.encoded_curve=None
        return w
    def do_encode_message(self):
        params=self.selected_params();p,a,b,G,n,h=params
        raw=(self.encode_text.text().encode('utf-8') if self.encode_fmt.currentIndex()==0 else hbytes(self.encode_text.text()))
        M,counter=encode_message_point(raw,params)
        recovered,_=decode_message_point(M,params)
        if recovered!=raw:raise ValueError('Encoding round-trip failed')
        self.encoded_point=M;self.encoded_curve=self.curve
        self.o6.setPlainText(f'CURVE: {self.curve}\nPlaintext bytes: {len(raw)}; maximum: {point_payload_capacity(p)}\n'
            f'Plaintext HEX: {raw.hex()}\nCounter: {counter}\n'
            f'M.x:\n{pretty(M[0])}\nM.y:\n{pretty(M[1])}\n'
            f'M (SEC1 uncompressed HEX):\n{encode(M,p).hex()}\n'
            f'M (SEC1 compressed HEX):\n{encode(M,p,True).hex()}\n'
            'Checks: on-curve, [n]M=O, and reversible decode PASSED.\n'
            'WARNING: deterministic teaching encoding, not a secure standardized encoding.')
    def send_encoded_to_encrypt(self):
        if self.encoded_point is None:raise ValueError('Encode a plaintext first')
        if self.encoded_curve!=self.curve_combo.currentText():raise ValueError('Selected curve changed since encoding')
        p,*_=self.selected_params()
        self.msg.setText(encode(self.encoded_point,p,self.msg_fmt.currentIndex()==1).hex())
        self.tabs.setCurrentIndex(3)
    def save_encoded_point(self):
        if self.encoded_point is None:raise ValueError('Encode a plaintext first')
        if self.encoded_curve!=self.curve_combo.currentText():raise ValueError('Curve changed since encoding')
        fmt=self.encode_save_fmt.currentText();ext='.bin' if fmt=='Binary (.bin)' else '.hex'
        path=self.save_path('Save encoded message point','encoded_message_point'+ext)
        if path:
            write_data(Path(path),encode(self.encoded_point,self.selected_params()[0]),fmt)
            self.o6.append(f'\nEncoded point saved: {path}')

    # Tab 7: reverse the encoding, after EC ElGamal decryption.
    def tab7(self):
        w,l=self.page('<b>Decode recovered EC point:</b> recover the original short UTF-8/HEX plaintext from the Week 8 reversible encoding. Use Tab 5 to decrypt first, or load a previously encoded SEC1 point.')
        f=self.group(l,'Point input')
        self.decode_fmt=self.fmt_combo(['SEC1 point HEX (paste)','SEC1 HEX file (.hex)','SEC1 binary file (.bin)']);f.addRow('Point format:',self.decode_fmt)
        self.decode_point_text=QLineEdit();self.decode_point_text.setPlaceholderText('Paste SEC1 04... / 02... / 03... point HEX');f.addRow('Point HEX:',self.decode_point_text)
        b=QPushButton('Load Point from File');b.clicked.connect(lambda:self.safe(self.load_point_for_decode));f.addRow(b)
        b=QPushButton('Use Recovered Point from Tab 5');b.clicked.connect(lambda:self.safe(self.use_decrypted_point));f.addRow(b)
        b=QPushButton('Decode Point to Plaintext');b.clicked.connect(lambda:self.safe(self.do_decode_message));f.addRow(b)
        f=self.group(l,'Save Recovered Plaintext')
        self.decode_save_fmt=self.fmt_combo(['Text UTF-8 (.txt)','Hex text (.hex)','Binary (.bin)']);f.addRow('Format:',self.decode_save_fmt)
        b=QPushButton('Save Plaintext');b.clicked.connect(lambda:self.safe(self.save_decoded_message));f.addRow(b)
        self.o7=self.output(l);self.decoded_message=None
        return w
    def load_point_for_decode(self):
        path=self.open_path('Load SEC1 encoded EC point')
        if not path:return
        mode=self.decode_fmt.currentText()
        raw=Path(path).read_bytes() if 'binary file' in mode else hbytes(Path(path).read_text(encoding='utf-8'))
        self.decode_point_text.setText(raw.hex())
        self.o7.setPlainText(f'Loaded SEC1 point from {path}\nLength: {len(raw)} bytes')
    def use_decrypted_point(self):
        if self.recovered is None:raise ValueError('Decrypt EC ElGamal ciphertext in Tab 5 first')
        if self.ct_curve!=self.curve_combo.currentText():raise ValueError('Ciphertext curve does not match selected curve')
        p,*_=self.selected_params()
        self.decode_point_text.setText(encode(self.recovered,p).hex())
        self.tabs.setCurrentIndex(6)
    def do_decode_message(self):
        p,a,b,G,n,h=self.selected_params()
        M=decode(hbytes(self.decode_point_text.text()),p,a,b)
        raw,counter=decode_message_point(M,(p,a,b,G,n,h))
        self.decoded_message=raw
        try:message=raw.decode('utf-8')
        except UnicodeDecodeError:message='(not valid UTF-8; use HEX/BIN output)'
        self.o7.setPlainText(f'CURVE: {self.curve}\nRecovered point SEC1: {encode(M,p).hex()}\n'
            f'Embedded counter: {counter}\nRecovered bytes: {len(raw)}\n'
            f'Plaintext HEX: {raw.hex()}\nPlaintext UTF-8: {message}\n'
            'WARNING: only points generated by the Week 8 encoding scheme can be decoded.')
    def save_decoded_message(self):
        if self.decoded_message is None:raise ValueError('Decode an EC point first')
        mode=self.decode_save_fmt.currentText()
        ext='.txt' if mode.startswith('Text') else '.bin' if mode.startswith('Binary') else '.hex'
        path=self.save_path('Save recovered plaintext','decoded_plaintext'+ext)
        if path:
            if mode.startswith('Text'):
                Path(path).write_text(self.decoded_message.decode('utf-8'),encoding='utf-8')
            else:write_data(Path(path),self.decoded_message,'Binary (.bin)' if ext=='.bin' else 'Hex text (.hex)')
            self.o7.append(f'\nPlaintext saved: {path}')


def main():
    app=QApplication(sys.argv);app.setFont(QFont('Arial',14));win=MainWindow();win.show();sys.exit(app.exec())
if __name__=='__main__':main()
