"""Week 08: ECDHE OpenSSL/PyQt6 laboratory. Requires PyQt6 and OpenSSL 3.x.
Tabs: configuration, named curves, endpoint key pair, peer derivation, HKDF.
DER .bin/.hex files are ASN.1-encoded keys, NOT raw scalar/point bytes.
"""
from __future__ import annotations
import re, shutil, subprocess, sys, tempfile
from pathlib import Path
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QApplication,QMainWindow,QTabWidget,QWidget,QVBoxLayout,QFormLayout,QGroupBox,QLabel,QLineEdit,QPushButton,QTextEdit,QComboBox,QFileDialog,QSpinBox,QCheckBox,QHBoxLayout,QMessageBox)

OUT=Path.cwd()/ 'week08_ecdhe_output'
OUT.mkdir(exist_ok=True)
# Curated well-known curves plus live discovery from the selected OpenSSL build.
# Legacy curves are included for comparison, not recommended for new systems.
CURVES = ['prime256v1', 'secp384r1', 'secp521r1', 'secp256k1',
          'secp224r1', 'prime192v1', 'brainpoolP256r1', 'brainpoolP384r1',
          'brainpoolP512r1', 'SM2']

def available_ec_curves(ssl):
    import re
    output = ssl.text('ecparam', '-list_curves')
    found = []
    for line in output.splitlines():
        match = re.match(r'^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.+)$', line)
        if match:
            found.append((match.group(1), match.group(2)))
    return found

def curve_family(description):
    if 'binary field' in description.lower():
        return 'Binary-field (legacy/teaching)'
    if 'brainpool' in description.lower():
        return 'Brainpool'
    return 'Prime-field'

FORMATS=['PEM (.pem)','DER binary (.bin)','DER hex (.hex)']
DATA_FORMATS=['Hex text (.hex)','Binary (.bin)']

def hex_lines(data):
    h=data.hex(); return '\n'.join(h[i:i+64] for i in range(0,len(h),64))

def read_hex(path):
    s=re.sub(r'\s|:', '',path.read_text(encoding='utf8'))
    if s.lower().startswith('0x'): s=s[2:]
    return bytes.fromhex(s)

def save_bytes(path,data,mode):
    if mode.startswith('Binary'): path.write_bytes(data)
    else: path.write_text(hex_lines(data)+'\n',encoding='utf8')

class OpenSSL:
    def __init__(self): self.binary=shutil.which('openssl') or 'openssl'
    def run(self,*args):
        cmd=[self.binary,*map(str,args)]
        p=subprocess.run(cmd,capture_output=True)
        if p.returncode:
            raise RuntimeError('OpenSSL failed: '+' '.join(cmd[:3])+'\n'+p.stderr.decode(errors='replace'))
        return p.stdout
    def text(self,*args): return self.run(*args).decode(errors='replace')

class Window(QMainWindow):
    def __init__(self):
        super().__init__(); self.resize(1200,850); self.setWindowTitle('Week 08 — ECDHE with OpenSSL: Curve, Shares, Z, HKDF')
        self.ssl=OpenSSL(); self.curve='prime256v1'; self.private=OUT/'endpoint_private.pem'; self.public=OUT/'endpoint_public.pem'
        self.normal_private=OUT/'loaded_local_private.pem'; self.normal_peer=OUT/'loaded_peer_public.pem'
        self.z=None; self.k=None; self.loaded_z=None; self.key_curve=None; self.local_path=None; self.peer_path=None
        self.tabs=QTabWidget(); self.setCentralWidget(self.tabs)
        for label,fn in [('1. OpenSSL Settings',self.tab1),('2. Standard EC Curves',self.tab2),('3. Ephemeral Key Shares',self.tab3),('4. Shared Secret Z',self.tab4),('5. Shared Key K',self.tab5)]: self.tabs.addTab(fn(),label)

    def error(self,e): QMessageBox.critical(self,'Error',str(e))
    def output(self,layout):
        o=QTextEdit(); o.setReadOnly(True); o.setFont(QFont('Consolas',10)); layout.addWidget(o); return o
    def button(self,layout,text,callback):
        b=QPushButton(text); b.clicked.connect(callback); layout.addWidget(b); return b
    def label(self,layout,text):
        x=QLabel(text); x.setWordWrap(True); layout.addWidget(x)
    def sync(self): self.ssl.binary=self.openssl_path.text().strip() or 'openssl'
    def browse(self,field,save=False,default='',filter='All files (*)'):
        if save: name,_=QFileDialog.getSaveFileName(self,'Save',default,filter)
        else: name,_=QFileDialog.getOpenFileName(self,'Open',default,filter)
        if name and field is not None: field.setText(name)
        return Path(name) if name else None
    def need(self,path):
        if not path.exists(): raise RuntimeError('File missing: '+str(path))
    def tab1(self):
        w=QWidget(); l=QVBoxLayout(w); self.label(l,'OpenSSL 3.x performs all EC key generation, ECDH and HKDF operations. Python handles file I/O and GUI.')
        f=QFormLayout(); self.openssl_path=QLineEdit(self.ssl.binary); f.addRow('OpenSSL executable:',self.openssl_path); l.addLayout(f)
        self.button(l,'Browse OpenSSL...',lambda:self.browse(self.openssl_path,filter='Executables (*.exe);;All files (*)'))
        self.button(l,'Test OpenSSL',self.test_ssl); self.o1=self.output(l); return w
    def test_ssl(self):
        try:
            self.sync(); self.o1.setPlainText(self.ssl.text('version','-a')+'\nPROVIDERS\n'+self.ssl.text('list','-providers')+'\nWorking directory: '+str(OUT))
        except Exception as e:self.error(e)
    def tab2(self):
        w=QWidget();l=QVBoxLayout(w); self.label(l,'Choose from EC curves reported by your OpenSSL installation (prime-field, Brainpool, and legacy binary-field curves). Inspect field, coefficients, G, n, h. Some listed legacy curves may be disabled by provider policy.')
        f=QFormLayout(); self.curves=QComboBox(); self.curves.addItems(CURVES)
        f.addRow('Named curve:',self.curves);l.addLayout(f)
        self.button(l,'Refresh curves from selected OpenSSL',self.refresh_curves)
        self.curve_description=QLabel('The list is populated from OpenSSL; legacy curves are for study only.')
        self.curve_description.setWordWrap(True);l.addWidget(self.curve_description)
        self.curves.currentIndexChanged.connect(self.describe_curve)
        self.refresh_curves()
        self.button(l,'Inspect EC Parameters (named and explicit)',self.inspect_curve);self.o2=self.output(l);return w
    def refresh_curves(self):
        try:
            self.sync()
            found = available_ec_curves(self.ssl)
            if not found:
                raise RuntimeError('No curves were returned by openssl ecparam -list_curves')
            previous = self.curves.currentText() or 'prime256v1'
            by_name = dict(found)
            names = [n for n in CURVES if n in by_name]
            names.extend(n for n, _ in found if n not in names)
            self.curves.blockSignals(True)
            self.curves.clear()
            for name in names:
                description = by_name[name]
                self.curves.addItem(name, description)
                self.curves.setItemData(self.curves.count()-1, description, 3)
            self.curves.setCurrentIndex(max(0, self.curves.findText(previous)))
            self.curves.blockSignals(False)
            self.describe_curve()
        except Exception as e:
            self.error(e)

    def describe_curve(self):
        description = self.curves.currentData() or ''
        family = curve_family(description)
        self.curve_description.setText(
            f'Family: {family} | {description}. '
            'Availability is OpenSSL-build/provider-dependent. '
            'Legacy and binary-field curves are included for academic comparison; '
            'prefer modern standardized curves for new deployments.')

    def inspect_curve(self):
        try:
            self.sync();self.curve=self.curves.currentText()
            named=self.ssl.text('ecparam','-name',self.curve,'-text','-noout')
            explicit=self.ssl.text('ecparam','-name',self.curve,'-param_enc','explicit','-text','-noout')
            family = curve_family(self.curves.currentData() or '')
            math_note = ('Prime-field: E(F_p): y²=x³+ax+b mod p.' if family != 'Binary-field (legacy/teaching)' else
                         'Binary-field: E(F_2^m): y²+xy=x³+ax²+b (ordinary binary curves).')
            self.o2.setPlainText('CURVE: '+self.curve+'\nFAMILY: '+family+'\n\nNAMED GROUP\n'+named+'\nEXPLICIT PARAMETERS\n'+explicit+'\n'+math_note+'\nG has order n; #E=h*n. Cofactor h is not the base-point order.\nSome legacy curves may be unavailable for key generation in the active provider.')
        except Exception as e:self.error(e)
    def tab3(self):
        w=QWidget();l=QVBoxLayout(w);self.label(l,'Generate ONE endpoint ephemeral EC key pair. Q=[d]G. Export private and public keys independently in PEM or DER (binary/hex). Only share the public key.')
        self.button(l,'Generate This Side’s Ephemeral EC Key Pair',self.generate)
        self.details=QCheckBox('Show explicit curve parameters p, a, b, G, n, h');l.addWidget(self.details)
        for title,attr,callback in [('Save Local Private Key','private_format',self.save_private),('Save Public Share for Peer','public_format',self.save_public)]:
            box=QGroupBox(title);f=QFormLayout(box);combo=QComboBox();combo.addItems(FORMATS);setattr(self,attr,combo);f.addRow('Format:',combo);b=QPushButton('Save As...');b.clicked.connect(callback);f.addRow(b);l.addWidget(box)
        self.o3=self.output(l);return w
    def generate(self):
        try:
            self.sync();self.curve=self.curves.currentText();self.key_curve=self.curve
            self.ssl.run('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:'+self.curve,'-out',self.private)
            self.ssl.run('pkey','-in',self.private,'-pubout','-out',self.public)
            p=self.ssl.text('pkey','-in',self.private,'-text','-noout');q=self.ssl.text('pkey','-pubin','-in',self.public,'-text','-noout')
            extra=self.ssl.text('ecparam','-name',self.curve,'-param_enc','explicit','-text','-noout') if self.details.isChecked() else ''
            self.o3.setPlainText('CURVE: '+self.curve+'\n'+extra+'\nLOCAL PRIVATE (KEEP SECRET)\n'+p+'\nPUBLIC SHARE Q=[d]G\n'+q+'\nWorking files:\n'+str(self.private)+'\n'+str(self.public))
        except Exception as e:self.error(e)
    def export(self,private):
        self.sync();src=self.private if private else self.public;self.need(src)
        mode=(self.private_format if private else self.public_format).currentText()
        default=('ec_private' if private else 'ec_public')+('.pem' if mode.startswith('PEM') else '.bin' if 'binary' in mode else '.hex')
        dest=self.browse(None,True,default,'PEM (*.pem);;Binary (*.bin);;Hex text (*.hex);;All files (*)')
        if not dest:return
        args=['pkey']+([] if private else ['-pubin'])+['-in',str(src)]+([] if private else ['-pubout'])
        if mode.startswith('PEM'):self.ssl.run(*args,'-out',dest)
        else:
            der=self.ssl.run(*args,'-outform','DER');save_bytes(dest,der,'Binary (.bin)' if 'binary' in mode else 'Hex text (.hex)')
        self.o3.append('\nSAVED '+('PRIVATE' if private else 'PUBLIC')+': '+str(dest)+' ['+mode+']')
    def save_private(self):
        try:self.export(True)
        except Exception as e:self.error(e)
    def save_public(self):
        try:self.export(False)
        except Exception as e:self.error(e)
    def tab4(self):
        w=QWidget();l=QVBoxLayout(w);self.label(l,'Load LOCAL private key and PEER public share. OpenSSL computes ECDH Z = x([d_local]Q_peer). Both keys must use the same curve.')
        for title,fmtattr,pathattr,cb in [('Input 1 — Local Private Key','in_private_format','in_private_path',self.load_private),('Input 2 — Peer Public Share','in_peer_format','in_peer_path',self.load_peer)]:
            box=QGroupBox(title);f=QFormLayout(box);c=QComboBox();c.addItems(FORMATS);setattr(self,fmtattr,c);f.addRow('Format:',c)
            p=QLineEdit();p.setReadOnly(True);setattr(self,pathattr,p);f.addRow('Loaded file:',p);b=QPushButton('Load...');b.clicked.connect(cb);f.addRow(b);l.addWidget(box)
        self.button(l,'Compute ECDH Shared Secret Z',self.compute_z)
        box=QGroupBox('Save Shared Secret Z');f=QFormLayout(box);self.z_format=QComboBox();self.z_format.addItems(DATA_FORMATS);f.addRow('Format:',self.z_format);b=QPushButton('Save Z As...');b.clicked.connect(self.save_z);f.addRow(b);l.addWidget(box)
        self.o4=self.output(l);return w
    def load_key(self,private):
        self.sync();mode=(self.in_private_format if private else self.in_peer_format).currentText()
        src=self.browse(None,False,filter='PEM (*.pem);;Binary (*.bin);;Hex text (*.hex);;All files (*)')
        if src is None:return
        dest=self.normal_private if private else self.normal_peer
        args=['pkey']+([] if private else ['-pubin'])
        if mode.startswith('PEM'):self.ssl.run(*args,'-in',src,*([] if private else ['-pubout']),'-out',dest)
        else:
            der=src.read_bytes() if 'binary' in mode else read_hex(src)
            with tempfile.TemporaryDirectory() as td:
                tmp=Path(td)/'key.der';tmp.write_bytes(der)
                self.ssl.run(*args,'-inform','DER','-in',tmp,*([] if private else ['-pubout']),'-out',dest)
        details=self.ssl.text('pkey',*([] if private else ['-pubin']),'-in',dest,'-text','-noout')
        if private:self.local_path=src;self.in_private_path.setText(str(src))
        else:self.peer_path=src;self.in_peer_path.setText(str(src))
        self.z=None;self.o4.append('\nLOADED '+('LOCAL PRIVATE' if private else 'PEER PUBLIC')+'\n'+details)
    def load_private(self):
        try:self.load_key(True)
        except Exception as e:self.normal_private.unlink(missing_ok=True);self.local_path=None;self.in_private_path.clear();self.error(e)
    def load_peer(self):
        try:self.load_key(False)
        except Exception as e:self.normal_peer.unlink(missing_ok=True);self.peer_path=None;self.in_peer_path.clear();self.error(e)
    def compute_z(self):
        try:
            self.sync()
            if self.local_path is None or self.peer_path is None:raise RuntimeError('Load both local private and peer public files first.')
            self.need(self.normal_private);self.need(self.normal_peer)
            with tempfile.TemporaryDirectory() as td:
                zfile=Path(td)/'z.bin';self.ssl.run('pkeyutl','-derive','-inkey',self.normal_private,'-peerkey',self.normal_peer,'-out',zfile);self.z=zfile.read_bytes()
            self.o4.append('\nECDH SHARED SECRET Z = x([d_local]Q_peer)\nLength: '+str(len(self.z))+' bytes\n'+hex_lines(self.z)+'\nRepeat at peer with peer private and this endpoint public; compare Z.')
        except Exception as e:self.error(e)
    def save_z(self):
        try:
            if self.z is None:raise RuntimeError('Compute Z first.')
            mode=self.z_format.currentText();path=self.browse(None,True,'ecdh_Z'+('.bin' if mode.startswith('Binary') else '.hex'))
            if path:save_bytes(path,self.z,mode);self.o4.append('Saved Z: '+str(path))
        except Exception as e:self.error(e)
    def tab5(self):
        w=QWidget();l=QVBoxLayout(w);self.label(l,'Load Z in HEX/BIN and derive application key K with OpenSSL HKDF. Both endpoints must use identical digest, salt, info and length.')
        f=QFormLayout();self.z_in_format=QComboBox();self.z_in_format.addItems(DATA_FORMATS);f.addRow('Z format:',self.z_in_format);self.z_in_path=QLineEdit();self.z_in_path.setReadOnly(True);f.addRow('Z file:',self.z_in_path);l.addLayout(f)
        self.button(l,'Load Shared Secret Z',self.load_z)
        box=QGroupBox('HKDF Parameters');f=QFormLayout(box);self.digest=QComboBox();self.digest.addItems(['SHA256','SHA384','SHA512']);f.addRow('Digest:',self.digest)
        self.klen=QSpinBox();self.klen.setRange(16,128);self.klen.setValue(32);f.addRow('Key length (bytes):',self.klen)
        self.salt=QLineEdit();self.salt.setPlaceholderText('Optional hex salt');f.addRow('Salt (hex):',self.salt)
        self.info=QLineEdit('Week08-ECDHE-session-key');f.addRow('Context / info:',self.info);l.addWidget(box)
        self.button(l,'Derive K with OpenSSL HKDF',self.derive_k)
        box=QGroupBox('Save Shared Key K');f=QFormLayout(box);self.k_format=QComboBox();self.k_format.addItems(DATA_FORMATS);f.addRow('Format:',self.k_format);b=QPushButton('Save K As...');b.clicked.connect(self.save_k);f.addRow(b);l.addWidget(box)
        self.o5=self.output(l);return w
    def load_z(self):
        try:
            path=self.browse(None,False,filter='Binary (*.bin);;Hex text (*.hex);;All files (*)')
            if not path:return
            mode=self.z_in_format.currentText();self.loaded_z=path.read_bytes() if mode.startswith('Binary') else read_hex(path)
            if not self.loaded_z:raise RuntimeError('Z is empty.')
            self.k=None;self.z_in_path.setText(str(path));self.o5.setPlainText('LOADED Z\n'+hex_lines(self.loaded_z))
        except Exception as e:self.loaded_z=None;self.error(e)
    def derive_k(self):
        try:
            self.sync()
            if self.loaded_z is None:raise RuntimeError('Load Z first.')
            salt=re.sub(r'\s|:', '',self.salt.text())
            if salt.lower().startswith('0x'):salt=salt[2:]
            if salt:bytes.fromhex(salt)
            args=['kdf','-keylen',str(self.klen.value()),'-kdfopt','digest:'+self.digest.currentText(),'-kdfopt','hexkey:'+self.loaded_z.hex()]
            if salt:args+=['-kdfopt','hexsalt:'+salt]
            if self.info.text():args+=['-kdfopt','hexinfo:'+self.info.text().encode('utf8').hex()]
            result=self.ssl.text(*args,'HKDF').strip();self.k=bytes.fromhex(re.sub(r'\s|:', '',result))
            if len(self.k)!=self.klen.value():raise RuntimeError('Unexpected HKDF length.')
            self.o5.append('\nHKDF-'+self.digest.currentText()+'\nK ('+str(len(self.k))+' bytes):\n'+hex_lines(self.k))
        except Exception as e:self.k=None;self.error(e)
    def save_k(self):
        try:
            if self.k is None:raise RuntimeError('Derive K first.')
            mode=self.k_format.currentText();path=self.browse(None,True,'ecdh_K'+('.bin' if mode.startswith('Binary') else '.hex'))
            if path:save_bytes(path,self.k,mode);self.o5.append('Saved K: '+str(path))
        except Exception as e:self.error(e)

def main():
    app=QApplication(sys.argv);app.setFont(QFont('Arial',14));window=Window();window.show();sys.exit(app.exec())
if __name__=='__main__':main()
