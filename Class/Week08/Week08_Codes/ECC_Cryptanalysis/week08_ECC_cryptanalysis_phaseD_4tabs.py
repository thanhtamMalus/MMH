#!/usr/bin/env python3
"""Week 08 ECC Cryptanalysis Phase D: 11 MOV/Frey-Rueck, 12 Smart,
13 Twist Security, 16 ECDLP Benchmark. Real SEC/NIST curves are analyzed;
small vulnerable curves are used where full algebraic attacks are feasible.
Optional SageMath enables pairing and p-adic computations.
Run --self-test without PyQt6. Educational local-only laboratory.
"""
from __future__ import annotations
import argparse, math, os, random, shutil, subprocess, sys, tempfile, time
from dataclasses import dataclass
from collections import Counter
try:
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    ec=None

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


REAL_CURVES = tuple(CURVES)

def number(text):
    return int(text.strip(), 0) if text.strip().lower().startswith(('0x','0b','0o')) else int(text.strip())

def small_prime_factors(n, limit=10000):
    """Trial division up to user-configurable bound; does NOT fully factor large integers."""
    result=[]; t=n
    for q in range(2, min(limit, math.isqrt(t))+1):
        if t%q==0:
            exponent=0
            while t%q==0:t//=q;exponent+=1
            result.append((q,exponent))
        if t==1:break
    return result,t

def embedding_degree(n,p,max_k):
    if math.gcd(n,p)!=1: return None
    v=p%n
    for k in range(1,max_k+1):
        if v==1:return k
        v=(v*p)%n
    return None

def count_curve(p,a,b):
    if p>50000:raise ValueError('Point enumeration is restricted to p <= 50000')
    sq=Counter((y*y)%p for y in range(p))
    return 1+sum(sq[(x*x*x+a*x+b)%p] for x in range(p))

def point_list(p,a,b):
    sq={}
    for y in range(p):sq.setdefault(y*y%p,[]).append(y)
    return [(x,y) for x in range(p) for y in sq.get((x*x*x+a*x+b)%p,[])]

def mov_analysis(curve_name,max_k=20,small_limit=10000):
    c=domain(curve_name); k=embedding_degree(c.n,c.p,max_k)
    factors,rem=small_prime_factors(c.n,small_limit)
    lines=[f'Curve: {c.name}',f'Field prime p: {c.p}',f'Base-point order n: {c.n}',
      f'Checked embedding degrees: 1..{max_k}',
      f'Embedding degree within checked range: {k if k is not None else "not found"}',
      f'Small factors of n (trial division): {factors}; remaining cofactor: {rem}',
      'MOV/Frey-Rueck reduction needs a pairing and finite-field DLP solver.',
      'No full ECDLP attack is claimed on this real standardized curve.']
    return '\n'.join(lines)

def anomalous_examples(max_p=127,limit=5):
    out=[]
    for p in range(5,max_p+1):
        if not is_small_prime(p):continue
        for a in range(p):
            for b in range(p):
                if (4*a*a*a+27*b*b)%p==0:continue
                if count_curve(p,a,b)==p:
                    out.append((p,a,b))
                    if len(out)>=limit:return out
    return out

def is_small_prime(n):
    if n<2:return False
    return all(n%d for d in range(2,math.isqrt(n)+1))

def smart_analysis(curve_name,search_p=31):
    c=domain(curve_name)
    # Standardized curves in this lab have #E = n (cofactor 1)
    total=c.n
    lines=[f'Curve: {c.name}',f'Known #E(F_p): {total}',f'Field prime p: {c.p}',
       f'Anomalous condition #E(F_p) = p: {total==c.p}',
       'Smart attack applies to anomalous curves, not arbitrary standardized curves.',
       'Small anomalous curve examples for mathematical study:']
    lines += [f'  y^2 = x^3 + {a}x + {b} over F_{p}, #E={p}' for p,a,b in anomalous_examples(search_p,3)]
    lines += ['For an actual Smart discrete-log recovery, use the optional SageMath p-adic backend.']
    return '\n'.join(lines)

def twist_analysis(curve_name,limit=10000):
    c=domain(curve_name)
    # Hasse: #E + #E_twist = 2(p+1). All listed curves have cofactor 1.
    N=c.n
    Nt=2*(c.p+1)-N
    factors,rem=small_prime_factors(Nt,limit)
    lines=[f'Curve: {c.name}',f'p bits: {c.p.bit_length()}',
       f'#E(F_p): {N}',f'Curve trace t = p+1-#E: {c.p+1-N}',
       f'Quadratic twist order #E_twist = 2(p+1)-#E: {Nt}',
       f'Twist order bits: {Nt.bit_length()}',
       f'Small prime-power factors (trial division <= {limit}): {factors}',
       f'Remaining cofactor (NOT necessarily prime): {rem}',
       'A twist is not the original curve. Public-point validation and subgroup checks matter.',
       'This is parameter analysis, not an exploit of a validated OpenSSL ECDH endpoint.']
    return '\n'.join(lines)

def bsgs(c,Q,B):
    m=math.isqrt(B)+1
    table={}; P=None
    for j in range(m):
        if P not in table:table[P]=j
        P=add(P,c.G,c)
    neg_mG=mul(-m,c.G,c)
    R=Q
    for i in range(m+1):
        j=table.get(R)
        if j is not None:
            d=i*m+j
            if 1<=d<=B and mul(d,c.G,c)==Q:return d,m+i+1
        R=add(R,neg_mG,c)
    return None,m+m+1

def brute(c,Q,B):
    P=None
    for d in range(1,B+1):
        P=add(P,c.G,c)
        if P==Q:return d,d
    return None,B

def kangaroo(c,Q,B,seed=1):
    """Pollard lambda for d in [1,B]. Expected O(sqrt(B)); heuristic randomized walks."""
    if B<1:return None,0
    rng=random.Random(seed)
    steps=[1<<i for i in range(max(1,min(12,math.isqrt(B).bit_length())))]
    # Use deterministic step selector; average step size is ~sqrt(B)/2.
    def jump(P):return steps[(P[0] if P is not None else 0)%len(steps)]
    tame=mul(B,c.G,c); tame_d=B
    rounds=max(80,12*math.isqrt(B))
    traps={}
    for _ in range(rounds):
        traps[tame]=tame_d
        j=jump(tame);tame=add(tame,mul(j,c.G,c),c);tame_d+=j
    wild=Q;wild_d=0
    for i in range(rounds+max(50,4*math.isqrt(B))):
        if wild in traps:
            candidate=traps[wild]-wild_d
            if 1<=candidate<=B and mul(candidate,c.G,c)==Q:
                return candidate,rounds+i+1
        j=jump(wild);wild=add(wild,mul(j,c.G,c),c);wild_d+=j
    return None,rounds*2+max(50,4*math.isqrt(B))

def benchmark(curve_name,d,B,algorithms=('Brute force','BSGS','Pollard kangaroo')):
    c=domain(curve_name)
    if not 1<=d<c.n:raise ValueError('Require 1 <= d < n')
    if not 1<=B<c.n:raise ValueError('Require 1 <= B < n')
    Q=mul(d,c.G,c)
    out=[f'Curve: {c.name}',f'Generator order bits: {c.n.bit_length()}',
       f'Private scalar d (challenge setup): {d}',f'Interval: [1,{B}]',
       f'Expected full-group generic work ~2^{(c.n.bit_length()-1)//2}',
       'NOTE: interval attacks exploit an artificially restricted key space, not a weak curve.']
    for name in algorithms:
        start=time.perf_counter()
        if name=='Brute force':found,ops=brute(c,Q,B)
        elif name=='BSGS':found,ops=bsgs(c,Q,B)
        elif name=='Pollard kangaroo':found,ops=kangaroo(c,Q,B)
        else:continue
        duration=time.perf_counter()-start
        out.append(f'{name}: recovered={found}, verified={found is not None and mul(found,c.G,c)==Q}, operations~{ops}, elapsed={duration:.6f}s')
    return '\n'.join(out)

SAGE_MOV = r'''# SageMath: Weil-pairing MOV reduction on a supersingular weak curve.
p = 43
E = EllipticCurve(GF(p), [1,0])
N = E.cardinality()
print('E(F_43) order:',N,'factorization:',factor(N))
ell = 11
assert N % ell == 0
P = next((T for T in E.points() if T.order() % ell == 0),None)
P = (P.order()//ell)*P
K = GF(p^2,'u')
EK = E.change_ring(K)
PK = EK(P)
# Pairing requires independent ell-torsion point over extension field.
Q = None
for attempt in range(200):
    candidate = (EK.cardinality()//ell) * EK.random_point()
    if candidate != EK(0) and candidate.order() == ell and PK.weil_pairing(candidate,ell) != 1:
        Q = candidate
        break
assert Q is not None, 'Unable to find independent torsion point'
d = 7
T = d*PK
alpha = PK.weil_pairing(Q,ell)
beta = T.weil_pairing(Q,ell)
recovered = discrete_log(beta,alpha,ord=ell)
print('embedding degree:',Mod(p,ell).multiplicative_order())
print('original d:',d,'recovered:',recovered)
assert recovered == d
'''

SAGE_SMART = r'''# SageMath p-adic Smart attack demonstration on a small anomalous curve.
p = 5
F = GF(p)
E = EllipticCurve(F,[3,2])
assert E.cardinality() == p
G = next(P for P in E.points() if P != E(0))
d = 3
Q = d*G
K = Qp(p,prec=20)
# Random integral lift of curve coefficients; a nonsingular p-adic lift.
Ek = EllipticCurve(K,[K(3),K(2)])
def lift(P):
    x = K(ZZ(P[0])); ys = Ek.lift_x(x,all=True)
    for T in ys:
        if ZZ(T[1].residue()) == ZZ(P[1]):return T
    raise RuntimeError('Point lift failed')
Gp = p*lift(G)
Qpnt = p*lift(Q)
def parameter(T):return -T[0]/T[1]
result = ZZ((parameter(Qpnt)/parameter(Gp)).residue()) % p
print('anomalous curve:', E, 'group order:', E.cardinality())
print('original d:',d,'recovered d:',result)
assert result == d
'''

def sage_run(source, timeout=45):
    sage=shutil.which('sage')
    if not sage:raise RuntimeError('SageMath executable not found in PATH. Use Export Sage Script and run in SageMath.')
    with tempfile.TemporaryDirectory(prefix='w08_phaseD_') as tmp:
        path=os.path.join(tmp,'demo.sage')
        with open(path,'w',encoding='utf8') as f:f.write(source)
        proc=subprocess.run([sage,path],capture_output=True,text=True,timeout=timeout)
        return f'Exit code: {proc.returncode}\n{proc.stdout}\n{proc.stderr}'

def self_test():
    for name in REAL_CURVES:
        c=domain(name)
        assert on_curve(c.G,c) and mul(c.n,c.G,c) is None
        Nt=2*(c.p+1)-c.n
        assert Nt>0
        assert embedding_degree(c.n,c.p,4) is None
        for d in (1,7,37):
            B=100
            Q=mul(d,c.G,c)
            assert brute(c,Q,B)[0]==d
            assert bsgs(c,Q,B)[0]==d
            assert kangaroo(c,Q,B)[0]==d
        print('PASS:',name,'twist, MOV screen, brute, BSGS, kangaroo')
    assert count_curve(5,3,2)==5
    print('PASS: anomalous toy example E(F_5)')


def launch_gui():
    from PyQt6.QtWidgets import (QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,
        QTabWidget,QLabel,QComboBox,QLineEdit,QPushButton,QPlainTextEdit,QMessageBox,
        QFileDialog,QSpinBox,QCheckBox)
    from PyQt6.QtCore import Qt

    class Lab(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle('Week 08 — Phase D: Advanced ECC Mathematics and Benchmarking')
            self.resize(1120,790)
            self.tabs=QTabWidget();self.setCentralWidget(self.tabs)
            self.outputs=[];self.curves=[]
            self.make_tab('11 — MOV / Frey–Rück',self.mov_tab)
            self.make_tab('12 — Smart Anomalous Curves',self.smart_tab)
            self.make_tab('13 — Twist Security',self.twist_tab)
            self.make_tab('16 — Comparative Benchmark',self.benchmark_tab)
            self.statusBar().showMessage('Standardized prime-field SEC curves; SageMath optional for advanced algebra')

        def make_tab(self,title,setup):
            page=QWidget();root=QVBoxLayout(page)
            desc=QLabel();desc.setWordWrap(True);root.addWidget(desc)
            curve=QComboBox();curve.addItems(REAL_CURVES)
            line=QHBoxLayout();line.addWidget(QLabel('Real standardized curve:'));line.addWidget(curve,1);root.addLayout(line)
            output=QPlainTextEdit();output.setReadOnly(True)
            self.outputs.append(output);self.curves.append(curve)
            setup(root,curve,output,desc)
            root.addWidget(output,1)
            actions=QHBoxLayout()
            copy=QPushButton('Copy Log');copy.clicked.connect(lambda: QApplication.clipboard().setText(output.toPlainText()))
            clear=QPushButton('Clear Log');clear.clicked.connect(output.clear)
            actions.addWidget(copy);actions.addWidget(clear);actions.addStretch(1)
            root.addLayout(actions)
            self.tabs.addTab(page,title)

        def append(self,out,func):
            try:
                out.appendPlainText(func()+'\n'+'-'*70+'\n')
            except Exception as e:
                out.appendPlainText('ERROR: '+str(e)+'\n')

        def param(self,root,label,value):
            row=QHBoxLayout();row.addWidget(QLabel(label));field=QLineEdit(str(value));row.addWidget(field,1);root.addLayout(row)
            return field

        def sage_actions(self,root,out,script):
            row=QHBoxLayout()
            save=QPushButton('Export SageMath .sage Script')
            def save_script():
                path,_=QFileDialog.getSaveFileName(self,'Export SageMath Script','week08_advanced_ecc.sage','SageMath (*.sage)')
                if path:
                    with open(path,'w',encoding='utf8') as f:f.write(script)
                    out.appendPlainText('Exported: '+path)
            save.clicked.connect(save_script)
            run=QPushButton('Run SageMath Backend (optional)')
            run.clicked.connect(lambda:self.append(out,lambda:sage_run(script)))
            row.addWidget(save);row.addWidget(run);root.addLayout(row)

        def mov_tab(self,root,curve,out,desc):
            desc.setText('11 — MOV/Frey–Rück: screen real curve embedding degree and subgroup order. '
                'Optional SageMath pairing demonstration uses a deliberately weak supersingular curve, '
                'not a standardized curve. Screening does NOT solve real-curve ECDLP.')
            degree=self.param(root,'Maximum embedding degree to check:',20)
            factor=self.param(root,'Small-factor trial division limit:',10000)
            run=QPushButton('Analyze Selected Standardized Curve')
            run.clicked.connect(lambda:self.append(out,lambda:mov_analysis(curve.currentText(),number(degree.text()),number(factor.text()))))
            root.addWidget(run);self.sage_actions(root,out,SAGE_MOV)

        def smart_tab(self,root,curve,out,desc):
            desc.setText('12 — Smart attack applies to anomalous curves with #E(F_p)=p. '
                'Inspect the real standardized curve, discover a small anomalous example, '
                'then use the optional SageMath p-adic attack demonstration.')
            prime=self.param(root,'Search toy anomalous examples up to prime:',17)
            run=QPushButton('Analyze Curve and Find Anomalous Example')
            run.clicked.connect(lambda:self.append(out,lambda:smart_analysis(curve.currentText(),number(prime.text()))))
            root.addWidget(run);self.sage_actions(root,out,SAGE_SMART)

        def twist_tab(self,root,curve,out,desc):
            desc.setText('13 — Compute the quadratic-twist group order from the real curve trace '
                'and inspect small factors. Cofactor and point validation are essential. '
                'This is a structural audit, not an attack on OpenSSL.')
            bound=self.param(root,'Trial division bound for twist order:',10000)
            run=QPushButton('Analyze Selected Real Curve and Twist')
            run.clicked.connect(lambda:self.append(out,lambda:twist_analysis(curve.currentText(),number(bound.text()))))
            root.addWidget(run)

        def benchmark_tab(self,root,curve,out,desc):
            desc.setText('16 — Run bounded ECDLP algorithms on the SAME real SEC curve and public key. '
                'A deliberately restricted scalar interval is NOT a weakness of the standardized curve. '
                'No hidden hardcoded search budget; large settings may take a long time.')
            d=self.param(root,'Private scalar d (decimal or 0x...):',12345)
            B=self.param(root,'Search interval maximum B (decimal or 0x...):',50000)
            checks=[]
            row=QHBoxLayout()
            for label in ('Brute force','BSGS','Pollard kangaroo'):
                check=QCheckBox(label);check.setChecked(True);row.addWidget(check);checks.append(check)
            root.addLayout(row)
            run=QPushButton('Run Comparative Benchmark')
            def execute():
                selected=[x.text() for x in checks if x.isChecked()]
                if not selected:raise ValueError('Select at least one algorithm')
                return benchmark(curve.currentText(),number(d.text()),number(B.text()),selected)
            run.clicked.connect(lambda:self.append(out,execute))
            root.addWidget(run)

    app=QApplication(sys.argv)
    app.setStyle('Fusion')
    w=Lab();w.show()
    return app.exec()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--list-curves',action='store_true')
    args=parser.parse_args()
    if args.self_test:self_test()
    elif args.list_curves:print('\n'.join(REAL_CURVES))
    else:
        try:sys.exit(launch_gui())
        except ImportError as e:
            print('GUI dependency missing: pip install PyQt6 cryptography\n',e,file=sys.stderr)
            sys.exit(1)
