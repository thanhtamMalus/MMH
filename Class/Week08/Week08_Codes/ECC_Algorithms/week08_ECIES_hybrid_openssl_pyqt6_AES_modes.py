"""Week 08 — ECIES-style hybrid authenticated encryption laboratory.
OpenSSL CLI: curve discovery, EC key generation, PEM/DER conversions, ECDH.
cryptography: HKDF-SHA256/384/512 and AES-GCM, AES-CTR+HMAC, or AES-CBC+HMAC.
This is a teaching-specific interoperable envelope, NOT standardized ECIES.
Install: pip install PyQt6 cryptography; OpenSSL 3.x on PATH.
"""
from __future__ import annotations
import base64, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QApplication,QMainWindow,QWidget,QTabWidget,QVBoxLayout,QHBoxLayout,
 QFormLayout,QGroupBox,QLabel,QLineEdit,QPushButton,QTextEdit,QComboBox,QFileDialog,QMessageBox,QCheckBox)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac
from cryptography.exceptions import InvalidSignature

OUT=Path.cwd()/"week08_ecies_output"; OUT.mkdir(parents=True,exist_ok=True)
KEY_FORMATS=['PEM (.pem)','DER binary (.bin)','DER hex (.hex)']
CT_FORMATS=['JSON (.json)','Binary (.bin)','Hex text (.hex)']
PREFERRED=['prime256v1','secp384r1','secp521r1','secp256k1','secp224r1','secp192r1',
 'brainpoolP256r1','brainpoolP384r1','brainpoolP512r1','SM2',
 'sect163r2','sect233r1','sect283r1','sect409r1','sect571r1']
MAGIC=b'ECIESLAB1\n'
CIPHERS=[f'AES-{bits}-{mode}' for mode in ('GCM','CTR+HMAC','CBC+HMAC') for bits in (128,192,256)]

def encrypt_symmetric(key_material, cipher_name, nonce, plaintext, aad):
 bits=int(cipher_name.split('-')[1]); key=key_material[:bits//8]
 if cipher_name.endswith('GCM'):
  return AESGCM(key).encrypt(nonce,plaintext,aad)
 if cipher_name.endswith('CTR+HMAC'):
  enc=Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
  ct=enc.update(plaintext)+enc.finalize()
 else:
  padder=padding.PKCS7(128).padder(); padded=padder.update(plaintext)+padder.finalize()
  enc=Cipher(algorithms.AES(key),modes.CBC(nonce)).encryptor()
  ct=enc.update(padded)+enc.finalize()
 mac=hmac.HMAC(key_material[bits//8:bits//8+32],hashes.SHA256())
 mac.update(len(aad).to_bytes(8,'big')+aad+nonce+ct)
 return ct+mac.finalize()

def decrypt_symmetric(key_material,cipher_name,nonce,data,aad):
 bits=int(cipher_name.split('-')[1]);key=key_material[:bits//8]
 if cipher_name.endswith('GCM'):
  return AESGCM(key).decrypt(nonce,data,aad)
 if len(data)<32:raise ValueError('Ciphertext missing HMAC tag')
 ct,tag=data[:-32],data[-32:]
 mac=hmac.HMAC(key_material[bits//8:bits//8+32],hashes.SHA256())
 mac.update(len(aad).to_bytes(8,'big')+aad+nonce+ct)
 mac.verify(tag) # Verify BEFORE decryption, including CBC unpadding
 if cipher_name.endswith('CTR+HMAC'):
  dec=Cipher(algorithms.AES(key),modes.CTR(nonce)).decryptor()
  return dec.update(ct)+dec.finalize()
 if len(ct)%16:raise ValueError('Invalid CBC ciphertext length')
 dec=Cipher(algorithms.AES(key),modes.CBC(nonce)).decryptor()
 padded=dec.update(ct)+dec.finalize()
 unpadder=padding.PKCS7(128).unpadder()
 return unpadder.update(padded)+unpadder.finalize()


def curve_alias(name):
 return {'secp256r1':'prime256v1'}.get(name,name)
MAX_INPUT=64*1024*1024

def hexbytes(s):
 s=''.join(s.split()).replace(':',''); s=s[2:] if s.lower().startswith('0x') else s
 if len(s)%2: raise ValueError('Hexadecimal input has odd length')
 return bytes.fromhex(s)

def pretty(b):
 h=b.hex();return '\n'.join(h[i:i+64] for i in range(0,len(h),64))

def read_key_bytes(path,fmt):
 if fmt=='DER hex (.hex)':return hexbytes(Path(path).read_text(encoding='utf-8'))
 return Path(path).read_bytes()

def kdf(z,salt,info,digest,length=32):
 alg={'SHA256':hashes.SHA256(),'SHA384':hashes.SHA384(),'SHA512':hashes.SHA512()}[digest]
 return HKDF(algorithm=alg,length=length,salt=salt,info=info).derive(z)

def b64(data):return base64.b64encode(data).decode('ascii')
def ub64(s):return base64.b64decode(s,validate=True)

def make_packet(ephemeral_der,salt,nonce,ciphertext,curve,digest,info,cipher_name="AES-256-GCM"):

 return {'format':'Week08-ECIES-LAB-v1','curve':curve,'kdf':'HKDF-'+digest,
         'cipher':cipher_name,'ephemeral_spki_der':b64(ephemeral_der),
         'salt':b64(salt),'nonce':b64(nonce),'info':b64(info),'ciphertext_tag':b64(ciphertext)}

def packet_bytes(packet):return json.dumps(packet,sort_keys=True,separators=(',',':')).encode('utf-8')

def aad_bytes(packet):
 # Authenticate metadata and ephemeral public key; ciphertext_tag is excluded.
 return packet_bytes({k:v for k,v in packet.items() if k!='ciphertext_tag'})

def packet_to_file(path,packet,fmt):
 data=packet_bytes(packet)
 if fmt=='JSON (.json)':Path(path).write_text(json.dumps(packet,indent=2)+'\n',encoding='utf-8')
 elif fmt=='Binary (.bin)':Path(path).write_bytes(MAGIC+data)
 else:Path(path).write_text(pretty(MAGIC+data)+'\n',encoding='utf-8')

def packet_from_file(path,fmt):
 if fmt=='JSON (.json)':raw=Path(path).read_bytes()
 elif fmt=='Binary (.bin)':raw=Path(path).read_bytes()
 else:raw=hexbytes(Path(path).read_text(encoding='utf-8'))
 if raw.startswith(MAGIC):raw=raw[len(MAGIC):]
 if len(raw)>MAX_INPUT+4096:raise ValueError('Envelope exceeds classroom size limit')
 packet=json.loads(raw.decode('utf-8'))
 required={'format','curve','kdf','cipher','ephemeral_spki_der','salt','nonce','info','ciphertext_tag'}
 if not isinstance(packet,dict) or set(packet)!=required or packet['format']!='Week08-ECIES-LAB-v1' or packet['cipher'] not in CIPHERS:
  raise ValueError('Invalid or unsupported ECIES laboratory envelope')
 if packet['kdf'] not in ('HKDF-SHA256','HKDF-SHA384','HKDF-SHA512'):raise ValueError('Unsupported KDF')
 return packet

class OpenSSL:
 def __init__(self):self.binary=shutil.which('openssl') or 'openssl'
 def run(self,args):
  cmd=[self.binary]+list(map(str,args))
  cp=subprocess.run(cmd,capture_output=True,timeout=90)
  if cp.returncode:raise RuntimeError('OpenSSL failed:\n'+' '.join(cmd)+'\n'+cp.stderr.decode(errors='replace'))
  return cp.stdout
 def text(self,args):return self.run(args).decode(errors='replace')

class MainWindow(QMainWindow):
 def __init__(self):
  super().__init__();self.setWindowTitle('Week 08 — ECIES-style Hybrid Encryption (OpenSSL + PyQt6)');self.resize(1250,870)
  self.ssl=OpenSSL();self.priv=OUT/'recipient_private.pem';self.pub=OUT/'recipient_public.pem'
  self.curve='prime256v1';self.loaded_pub=None;self.loaded_priv=None;self.packet=None;self.recovered=None
  self.enc_input=None;self.enc_input_kind='Text (UTF-8)'
  self.tabs=QTabWidget();self.setCentralWidget(self.tabs)
  for label,fn in [('1. OpenSSL Settings',self.tab1),('2. EC Curves / Parameters',self.tab2),
                   ('3. Recipient EC Key Pair',self.tab3),('4. Hybrid Encryption',self.tab4),
                   ('5. Hybrid Decryption',self.tab5)]:self.tabs.addTab(fn(),label)
 def log(self):
  w=QTextEdit();w.setReadOnly(True);f=QFont('Consolas');f.setStyleHint(QFont.StyleHint.Monospace);w.setFont(f);return w
 def error(self,e):QMessageBox.critical(self,'Error',str(e))
 def refresh(self):self.ssl.binary=self.sslpath.text().strip() or 'openssl'
 def choose(self,title,save=False,filter='All files (*)',default=''):
  fn=QFileDialog.getSaveFileName if save else QFileDialog.getOpenFileName
  p,_=fn(self,title,default,filter);return p
 def tab1(self):
  w=QWidget();v=QVBoxLayout(w);v.addWidget(QLabel('Configure OpenSSL 3.x. OpenSSL performs EC key generation and ECDH; cryptography performs HKDF and AES modes.'))
  g=QGroupBox('OpenSSL executable');f=QFormLayout(g);self.sslpath=QLineEdit(self.ssl.binary)
  row=QHBoxLayout();row.addWidget(self.sslpath);b=QPushButton('Browse');b.clicked.connect(lambda:self.sslpath.setText(self.choose('Select OpenSSL executable') or self.sslpath.text()));row.addWidget(b);f.addRow('Executable:',row)
  b=QPushButton('Test OpenSSL');b.clicked.connect(self.test_ssl);f.addRow(b);v.addWidget(g);self.o1=self.log();v.addWidget(self.o1);return w
 def test_ssl(self):
  try:self.refresh();self.o1.setPlainText(self.ssl.text(['version','-a'])+'\nPROVIDERS\n'+self.ssl.text(['list','-providers']))
  except Exception as e:self.error(e)
 def curves(self):
  s=self.ssl.text(['ecparam','-list_curves']);names=[]
  for line in s.splitlines():
   m=re.match(r'^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$',line)
   if m:names.append((m.group(1),m.group(2)))
  return sorted(names,key=lambda x:(x[0] not in PREFERRED,PREFERRED.index(x[0]) if x[0] in PREFERRED else x[0]))
 def tab2(self):
  w=QWidget();v=QVBoxLayout(w);v.addWidget(QLabel('Discover curves from the configured OpenSSL. Not every listed legacy curve is usable by active providers.'))
  g=QGroupBox('Curve selection');f=QFormLayout(g);self.curvecombo=QComboBox();self.curvecombo.addItems(PREFERRED);f.addRow('Named curve:',self.curvecombo)
  b=QPushButton('Refresh OpenSSL curve list');b.clicked.connect(self.refresh_curves);f.addRow(b)
  b=QPushButton('Inspect explicit EC parameters');b.clicked.connect(self.inspect_curve);f.addRow(b);v.addWidget(g);self.o2=self.log();v.addWidget(self.o2);return w
 def refresh_curves(self):
  try:
   self.refresh();items=self.curves();current=self.curvecombo.currentText();self.curvecombo.clear();self.curvecombo.addItems([n for n,d in items]);idx=self.curvecombo.findText(current)
   if idx>=0:self.curvecombo.setCurrentIndex(idx)
   self.o2.setPlainText('\n'.join(f'{n:22} {d}' for n,d in items))
  except Exception as e:self.error(e)
 def inspect_curve(self):
  try:
   self.refresh();self.curve=self.curvecombo.currentText();raw=self.ssl.text(['ecparam','-name',self.curve,'-param_enc','explicit','-text','-noout'])
   self.o2.setPlainText('Curve: '+self.curve+'\n\n'+raw+'\nNote: prime-field curves use y²=x³+ax+b mod p; binary-field curves use a different equation.')
  except Exception as e:self.error(e)
 def tab3(self):
  w=QWidget();v=QVBoxLayout(w);v.addWidget(QLabel('Generate a recipient key pair Q=[d]G using OpenSSL; export private/public keys independently.'))
  b=QPushButton('Generate Recipient EC Key Pair');b.clicked.connect(self.genkeys);v.addWidget(b)
  self.showparam=QCheckBox('Include explicit curve parameters in inspection');v.addWidget(self.showparam)
  for public in (False,True):
   g=QGroupBox('Save Public Key' if public else 'Save Private Key');f=QFormLayout(g);combo=QComboBox();combo.addItems(KEY_FORMATS)
   if public:self.pubfmt=combo
   else:self.privfmt=combo
   f.addRow('Format:',combo);b=QPushButton('Save Public Key As...' if public else 'Save Private Key As...');b.clicked.connect(lambda _,pub=public:self.save_key(pub));f.addRow(b);v.addWidget(g)
  self.o3=self.log();v.addWidget(self.o3);return w
 def genkeys(self):
  try:
   self.refresh();self.curve=self.curvecombo.currentText()
   self.ssl.run(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:'+self.curve,'-out',self.priv])
   self.ssl.run(['pkey','-in',self.priv,'-pubout','-out',self.pub])
   details=self.ssl.text(['pkey','-in',self.priv,'-text','-noout'])
   if self.showparam.isChecked():details+='\nDOMAIN PARAMETERS\n'+self.ssl.text(['ecparam','-name',self.curve,'-param_enc','explicit','-text','-noout'])
   self.o3.setPlainText('Curve: '+self.curve+'\nPrivate: '+str(self.priv)+'\nPublic: '+str(self.pub)+'\n\n'+details)
  except Exception as e:self.error(e)
 def save_key(self,public):
  try:
   self.refresh();source=self.pub if public else self.priv
   if not source.exists():raise ValueError('Generate keys in Tab 3 first')
   mode=self.pubfmt.currentText() if public else self.privfmt.currentText()
   ext='.pem' if mode==KEY_FORMATS[0] else '.bin' if mode==KEY_FORMATS[1] else '.hex'
   dest=self.choose('Save key',True,'All files (*)','ecies_'+('public' if public else 'private')+ext)
   if not dest:return
   args=['pkey']+(['-pubin'] if public else [])+['-in',source]+(['-pubout'] if public else [])
   if mode==KEY_FORMATS[0]:self.ssl.run(args+['-out',dest])
   else:
    der=self.ssl.run(args+['-outform','DER'])
    if mode==KEY_FORMATS[1]:Path(dest).write_bytes(der)
    else:Path(dest).write_text(pretty(der)+'\n',encoding='utf-8')
   self.o3.append('Saved '+('public' if public else 'private')+' key: '+dest)
  except Exception as e:self.error(e)
 def load_key(self,public,mode,source):
  self.refresh();data=read_key_bytes(source,mode)
  with tempfile.TemporaryDirectory(prefix='ecies_key_') as td:
   tmp=Path(td)/('input.pem' if mode==KEY_FORMATS[0] else 'input.der')
   tmp.write_bytes(data);args=['pkey']+(['-pubin'] if public else [])+['-in',tmp]
   if mode!=KEY_FORMATS[0]:args+=['-inform','DER']
   if public:args+=['-pubout']
   normalized=self.ssl.run(args+['-outform','PEM'])
  if public:
   key=serialization.load_pem_public_key(normalized)
   if not hasattr(key,'curve'):raise ValueError('Not an EC public key')
  else:
   key=serialization.load_pem_private_key(normalized,password=None)
   if not hasattr(key,'curve'):raise ValueError('Not an EC private key')
  return normalized,key
 def tab4(self):
  w=QWidget();v=QVBoxLayout(w);v.addWidget(QLabel('ECIES-style: ephemeral ECDH → HKDF → selectable AES modes (authenticated). Encrypt arbitrary UTF-8, HEX bytes, or a file.'))
  g=QGroupBox('Recipient Public Key');f=QFormLayout(g);self.encfmt=QComboBox();self.encfmt.addItems(KEY_FORMATS);f.addRow('Format:',self.encfmt)
  self.encpath=QLineEdit();self.encpath.setReadOnly(True);f.addRow('Loaded:',self.encpath)
  b=QPushButton('Load Recipient Public Key');b.clicked.connect(self.load_enc);f.addRow(b);v.addWidget(g)
  g=QGroupBox('Plaintext Input');f=QFormLayout(g);self.infmt=QComboBox();self.infmt.addItems(['Text (UTF-8)','Hex bytes','File']);f.addRow('Input type:',self.infmt)
  self.msg=QTextEdit();self.msg.setPlaceholderText('Enter UTF-8 text or hex bytes');self.msg.setMaximumHeight(95);f.addRow('Message:',self.msg)
  self.filepath=QLineEdit();self.filepath.setReadOnly(True);f.addRow('File:',self.filepath)
  b=QPushButton('Browse plaintext file');b.clicked.connect(lambda:self.filepath.setText(self.choose('Select plaintext file') or self.filepath.text()));f.addRow(b);v.addWidget(g)
  g=QGroupBox('HKDF + Authenticated Encryption');f=QFormLayout(g);self.digest=QComboBox();self.digest.addItems(['SHA256','SHA384','SHA512']);f.addRow('HKDF digest:',self.digest)
  self.cipher_combo=QComboBox();self.cipher_combo.addItems(CIPHERS);self.cipher_combo.setCurrentText('AES-256-GCM');f.addRow('AES algorithm and mode:',self.cipher_combo)
  self.info=QLineEdit('Week08-ECIES-session-key-v1');f.addRow('Context / info:',self.info)
  b=QPushButton('Encrypt with Fresh Ephemeral EC Key');b.clicked.connect(self.encrypt);f.addRow(b);v.addWidget(g)
  g=QGroupBox('Save Ciphertext Envelope');f=QFormLayout(g);self.ctfmt=QComboBox();self.ctfmt.addItems(CT_FORMATS);f.addRow('Format:',self.ctfmt)
  b=QPushButton('Save Ciphertext As...');b.clicked.connect(self.save_ct);f.addRow(b);v.addWidget(g)
  self.o4=self.log();v.addWidget(self.o4);return w
 def load_enc(self):
  try:
   p=self.choose('Load recipient public key');
   if not p:return
   self.loaded_pub_pem,self.loaded_pub=self.load_key(True,self.encfmt.currentText(),p);self.encpath.setText(p)
   self.o4.setPlainText('Public key loaded\nCurve: '+self.loaded_pub.curve.name+'\nSource: '+p)
  except Exception as e:self.error(e)
 def input_data(self):
  mode=self.infmt.currentText()
  if mode=='File':
   p=Path(self.filepath.text());
   if not p.is_file():raise ValueError('Select a plaintext file')
   if p.stat().st_size>MAX_INPUT:raise ValueError('Teaching demo file limit is 64 MiB')
   return p.read_bytes()
  s=self.msg.toPlainText();data=s.encode('utf-8') if mode=='Text (UTF-8)' else hexbytes(s)
  if len(data)>MAX_INPUT:raise ValueError('Input exceeds teaching demo limit')
  return data
 def ecdh(self,private_pem,public_pem):
  with tempfile.TemporaryDirectory(prefix='ecies_ecdh_') as td:
   priv=Path(td)/'local.pem';pub=Path(td)/'peer.pem';secret=Path(td)/'z.bin'
   priv.write_bytes(private_pem);pub.write_bytes(public_pem)
   self.ssl.run(['pkeyutl','-derive','-inkey',priv,'-peerkey',pub,'-out',secret])
   return secret.read_bytes()
 def encrypt(self):
  try:
   self.refresh()
   if self.loaded_pub is None:raise ValueError('Load recipient public key first')
   raw=self.input_data();curve=curve_alias(self.loaded_pub.curve.name)
   with tempfile.TemporaryDirectory(prefix='ecies_ephemeral_') as td:
    priv=Path(td)/'ephemeral_private.pem';pub=Path(td)/'ephemeral_public.pem'
    # Use the recipient curve as identified by the public key, not Tab 2 selection.
    self.ssl.run(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:'+curve,'-out',priv])
    self.ssl.run(['pkey','-in',priv,'-pubout','-out',pub])
    eph_der=self.ssl.run(['pkey','-pubin','-in',pub,'-pubout','-outform','DER'])
    z=self.ecdh(priv.read_bytes(),self.loaded_pub_pem)
   salt=os.urandom(32);cipher_name=self.cipher_combo.currentText();nonce=os.urandom(12 if cipher_name.endswith('GCM') else 16);info=self.info.text().encode('utf-8');digest=self.digest.currentText()
   packet=make_packet(eph_der,salt,nonce,b'',curve,digest,info,cipher_name)
   bits=int(cipher_name.split('-')[1]);key=kdf(z,salt,info,digest,bits//8+(0 if cipher_name.endswith('GCM') else 32));packet['ciphertext_tag']=b64(encrypt_symmetric(key,cipher_name,nonce,raw,aad_bytes(packet)))
   self.packet=packet
   self.o4.append('\nENCRYPTION SUCCESS\nCurve: '+curve+'\nECDH Z: '+str(len(z))+' bytes\nHKDF-'+digest+' → 32-byte AES key\nPlaintext: '+str(len(raw))+' bytes\nCiphertext+tag: '+str(len(ub64(packet['ciphertext_tag'])))+' bytes\nSalt: '+salt.hex()+'\nNonce: '+nonce.hex()+'\nEphemeral public SPKI DER:\n'+pretty(eph_der)+'\nMetadata authenticated as AAD or HMAC input. Secret Z and key K are not stored.')
  except Exception as e:self.error(e)
 def save_ct(self):
  try:
   if self.packet is None:raise ValueError('Encrypt first')
   fmt=self.ctfmt.currentText();ext='.json' if fmt==CT_FORMATS[0] else '.bin' if fmt==CT_FORMATS[1] else '.hex'
   p=self.choose('Save ciphertext envelope',True,'All files (*)','ecies_ciphertext'+ext)
   if p:packet_to_file(p,self.packet,fmt);self.o4.append('Saved: '+p)
  except Exception as e:self.error(e)
 def tab5(self):
  w=QWidget();v=QVBoxLayout(w);v.addWidget(QLabel('Load recipient private key and ciphertext independently; ECDH → HKDF → AES-GCM or Encrypt-then-HMAC verification and plaintext recovery.'))
  g=QGroupBox('Recipient Private Key');f=QFormLayout(g);self.decfmt=QComboBox();self.decfmt.addItems(KEY_FORMATS);f.addRow('Format:',self.decfmt)
  self.decpath=QLineEdit();self.decpath.setReadOnly(True);f.addRow('Loaded:',self.decpath)
  b=QPushButton('Load Recipient Private Key');b.clicked.connect(self.load_dec);f.addRow(b);v.addWidget(g)
  g=QGroupBox('Ciphertext Envelope');f=QFormLayout(g);self.decctfmt=QComboBox();self.decctfmt.addItems(CT_FORMATS);f.addRow('Format:',self.decctfmt)
  self.decctpath=QLineEdit();self.decctpath.setReadOnly(True);f.addRow('Loaded:',self.decctpath)
  b=QPushButton('Load Ciphertext');b.clicked.connect(self.load_ct);f.addRow(b)
  b=QPushButton('Decrypt and Authenticate');b.clicked.connect(self.decrypt);f.addRow(b);v.addWidget(g)
  g=QGroupBox('Recovered Plaintext');f=QFormLayout(g);self.recfmt=QComboBox();self.recfmt.addItems(['Text (UTF-8)','Hex text (.hex)','Binary (.bin)']);f.addRow('Save format:',self.recfmt)
  b=QPushButton('Save Recovered Plaintext As...');b.clicked.connect(self.save_recovered);f.addRow(b);v.addWidget(g)
  self.o5=self.log();v.addWidget(self.o5);return w
 def load_dec(self):
  try:
   p=self.choose('Load recipient private key');
   if not p:return
   self.loaded_priv_pem,self.loaded_priv=self.load_key(False,self.decfmt.currentText(),p);self.decpath.setText(p)
   self.o5.setPlainText('Private key loaded\nCurve: '+self.loaded_priv.curve.name+'\nSource: '+p)
  except Exception as e:self.error(e)
 def load_ct(self):
  try:
   p=self.choose('Load ciphertext envelope');
   if not p:return
   self.dec_packet=packet_from_file(p,self.decctfmt.currentText());self.decctpath.setText(p)
   self.o5.append('\nEnvelope loaded: '+p+'\nCurve: '+self.dec_packet['curve']+'\nKDF: '+self.dec_packet['kdf']+'\nCipher: '+self.dec_packet['cipher'])
  except Exception as e:self.error(e)
 def decrypt(self):
  try:
   self.refresh()
   if self.loaded_priv is None or not hasattr(self,'dec_packet'):raise ValueError('Load recipient private key and ciphertext first')
   packet=self.dec_packet;curve=curve_alias(self.loaded_priv.curve.name)
   if packet['curve']!=curve:raise ValueError('Curve mismatch: private key uses '+curve+', envelope uses '+packet['curve'])
   eph_der=ub64(packet['ephemeral_spki_der']);ephemeral=serialization.load_der_public_key(eph_der)
   if not hasattr(ephemeral,'curve') or curve_alias(ephemeral.curve.name)!=curve:raise ValueError('Invalid ephemeral EC public key or curve mismatch')
   eph_pem=ephemeral.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
   salt=ub64(packet['salt']);nonce=ub64(packet['nonce']);info=ub64(packet['info']);ct=ub64(packet['ciphertext_tag'])
   cipher_name=packet['cipher'];expected_nonce=12 if cipher_name.endswith('GCM') else 16
   if len(salt)!=32 or len(nonce)!=expected_nonce or len(ct)<(16 if cipher_name.endswith('GCM') else 32):raise ValueError('Invalid salt, nonce, or ciphertext length')
   digest=packet['kdf'].removeprefix('HKDF-');z=self.ecdh(self.loaded_priv_pem,eph_pem)
   bits=int(cipher_name.split('-')[1]);key=kdf(z,salt,info,digest,bits//8+(0 if cipher_name.endswith('GCM') else 32))
   # Authenticate before releasing plaintext.
   recovered=decrypt_symmetric(key,cipher_name,nonce,ct,aad_bytes(packet))
   self.recovered=recovered
   try:display=recovered.decode('utf-8')
   except UnicodeDecodeError:display='(not valid UTF-8; save as binary or HEX)'
   self.o5.append('\nAUTHENTICATION PASSED — DECRYPTION SUCCESS\nRecovered bytes: '+str(len(recovered))+'\nUTF-8 preview (first 4000 chars):\n'+display[:4000]+'\nHEX preview (first 256 bytes):\n'+pretty(recovered[:256]))
  except Exception as e:
   self.recovered=None;self.error(e)
 def save_recovered(self):
  try:
   if self.recovered is None:raise ValueError('Decrypt and authenticate first')
   fmt=self.recfmt.currentText();ext='.txt' if fmt=='Text (UTF-8)' else '.hex' if fmt=='Hex text (.hex)' else '.bin'
   p=self.choose('Save recovered plaintext',True,'All files (*)','ecies_recovered'+ext)
   if not p:return
   if fmt=='Text (UTF-8)':Path(p).write_text(self.recovered.decode('utf-8'),encoding='utf-8')
   elif fmt=='Hex text (.hex)':Path(p).write_text(pretty(self.recovered)+'\n',encoding='utf-8')
   else:Path(p).write_bytes(self.recovered)
   self.o5.append('Saved recovered plaintext: '+p)
  except Exception as e:self.error(e)

def main():
 app=QApplication(sys.argv);app.setFont(QFont('Arial',14));w=MainWindow();w.show();sys.exit(app.exec())
if __name__=='__main__':main()
