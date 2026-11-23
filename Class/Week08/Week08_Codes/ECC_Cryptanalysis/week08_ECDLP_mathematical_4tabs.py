#!/usr/bin/env python3
"""Week 08: ECDLP mathematical cryptanalysis laboratory (four PyQt6 tabs).
Pure-Python prime-field arithmetic on toy and historical SEC curves; user-configurable search intervals and operation budgets without a hardcoded maximum.
Dependencies: pip install PyQt6
"""
from __future__ import annotations
import math, random, time, sys, subprocess, re, shutil
from dataclasses import dataclass
from typing import Optional

Point = Optional[tuple[int,int]]  # None denotes infinity

@dataclass(frozen=True)
class Curve:
    p:int; a:int; b:int; G:Point; n:int; name:str
    def __post_init__(self):
        if self.p < 5 or not is_prime(self.p): raise ValueError('p must be an odd prime >= 5')
        if (4*self.a**3+27*self.b**2)%self.p==0: raise ValueError('Singular curve')
        if not on_curve(self,self.G): raise ValueError('G is not on the curve')
        if self.n<2 or mul(self,self.n,self.G) is not None: raise ValueError('Invalid generator order')
        if self.n <= 100000:
            for q in factor(self.n):
                if mul(self,self.n//q,self.G) is None: raise ValueError('n is not the exact order of G')

def is_prime(n):
    """Fast probable-prime screening; OpenSSL is authoritative for named curves."""
    if n < 2: return False
    for small in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n == small: return True
        if n % small == 0: return False
    d=n-1; r=0
    while d%2==0: d//=2; r+=1
    for base in (2,325,9375,28178,450775,9780504,1795265022) if n < 2**64 else (2,3,5,7,11,13,17,19,23,29,31,37,41,43):
        a=base%n
        if a==0: continue
        x=pow(a,d,n)
        if x in (1,n-1):continue
        for _ in range(r-1):
            x=pow(x,2,n)
            if x==n-1:break
        else:return False
    return True

def factor(n):
    out={}; d=2
    while d*d<=n:
        while n%d==0:out[d]=out.get(d,0)+1;n//=d
        d+=1
    if n>1:out[n]=out.get(n,0)+1
    return out

def on_curve(c,P):
    if P is None:return True
    x,y=P
    return 0<=x<c.p and 0<=y<c.p and (y*y-x*x*x-c.a*x-c.b)%c.p==0

def neg(c,P):return None if P is None else (P[0],(-P[1])%c.p)

def add(c,P,Q):
    if P is None:return Q
    if Q is None:return P
    x1,y1=P;x2,y2=Q;p=c.p
    if x1==x2 and (y1+y2)%p==0:return None
    if P==Q:
        if y1==0:return None
        lam=((3*x1*x1+c.a)*pow(2*y1,-1,p))%p
    else:lam=((y2-y1)*pow((x2-x1)%p,-1,p))%p
    x3=(lam*lam-x1-x2)%p
    return x3,(lam*(x1-x3)-y1)%p

def mul(c,k,P):
    if k<0:return mul(c,-k,neg(c,P))
    R=None
    while k:
        if k&1:R=add(c,R,P)
        P=add(c,P,P);k>>=1
    return R

def enumerate_points(p,a,b):
    if p>5000:raise ValueError('Toy curve p must be <= 5000')
    y_by_square={}
    for y in range(p):y_by_square.setdefault(y*y%p,[]).append(y)
    return [(x,y) for x in range(p) for y in y_by_square.get((x*x*x+a*x+b)%p,[])]

def point_order(c,P,limit):
    R=None
    for n in range(1,limit+1):
        R=add(c,R,P)
        if R is None:return n
    raise ValueError('Point order not found')

def make_curve(p,a,b,x,y):
    if not is_prime(p) or p<5 or p>5000:raise ValueError('Choose a prime p between 5 and 5000')
    a%=p;b%=p
    if (4*a**3+27*b*b)%p==0:raise ValueError('Singular curve')
    tmp=object.__new__(Curve)
    object.__setattr__(tmp,'p',p);object.__setattr__(tmp,'a',a);object.__setattr__(tmp,'b',b)
    P=(x,y)
    if not on_curve(tmp,P):raise ValueError('G is not on the curve')
    points=enumerate_points(p,a,b)
    n=point_order(tmp,P,len(points)+1)
    return Curve(p,a,b,P,n,f'Toy E(F_{p})')

# Small well-known teaching curve and generated small examples
PRESETS=[('E(17): y²=x³+2x+2, G=(5,1)',17,2,2,5,1),
         ('E(97): y²=x³+2x+3, G=(3,6)',97,2,3,3,6),
         ('E(223): y²=x³+7, G=(47,71)',223,0,7,47,71)]

# Historical SEC curves are real named standards, but their 56–80-bit
# generic ECDLP strength is far beyond an interactive Python laboratory.
HISTORICAL_CURVES = ('secp112r1','secp112r2','secp128r1','secp128r2','secp160k1','secp160r1','secp160r2')
MAX_ATTACK_ORDER = 100000
MAX_WORK = 200000


def openssl_named_curve(name, executable='openssl'):
    """Read explicit prime-field domain parameters from local OpenSSL."""
    if name not in HISTORICAL_CURVES:
        raise ValueError('Curve is not in the curated historical SEC list')
    try:
        cp=subprocess.run([executable,'ecparam','-name',name,'-param_enc','explicit','-text','-noout'],
                          capture_output=True,text=True,timeout=12,check=True)
    except (OSError,subprocess.SubprocessError) as exc:
        raise ValueError(f'OpenSSL could not load {name}: {exc}') from exc
    text=cp.stdout
    if 'Field Type: prime-field' not in text:
        raise ValueError('Only prime-field Weierstrass curves supported')
    def get_hex_section(label):
        m=re.search(r'^'+re.escape(label)+r':\s*\n((?:\s+[0-9a-fA-F:]+\s*\n)+)',text,re.M)
        if not m:raise ValueError(f'Could not parse {label} from OpenSSL')
        return bytes.fromhex(re.sub(r'[^0-9a-fA-F]','',m.group(1)))
    def get_value(label):
        m=re.search(r'^'+re.escape(label)+r':[ \t]*(?:\n((?:\s+[0-9a-fA-F:]+\s*\n)+)|([0-9]+)(?: \(0x[0-9a-fA-F]+\))?)',text,re.M)
        if not m:raise ValueError(f'Could not parse {label} from OpenSSL')
        return int(re.sub(r'[^0-9a-fA-F]','',m.group(1)),16) if m.group(1) else int(m.group(2))
    p=get_value('Prime');a=get_value('A');b=get_value('B');n=get_value('Order')
    h_match=re.search(r'^Cofactor:\s*(\d+)',text,re.M)
    h=int(h_match.group(1)) if h_match else None
    gen=get_hex_section('Generator (uncompressed)')
    size=(p.bit_length()+7)//8
    if len(gen)!=1+2*size or gen[0]!=4:raise ValueError('Malformed SEC1 generator')
    gx=int.from_bytes(gen[1:1+size],'big');gy=int.from_bytes(gen[1+size:],'big')
    c=Curve(p,a,b,(gx,gy),n,name)
    return c,h

def brute(c,Q,limit=100000,trace=30):
    if c.n>limit:raise ValueError(f'Order {c.n} exceeds brute-force limit {limit}')
    R=None;log=[]
    for d in range(c.n):
        if d<trace:log.append(f'd={d:>5}  [d]G={fmt(R)}')
        if R==Q:return d,d+1,log
        R=add(c,R,c.G)
    return None,c.n,log

def bsgs(c,Q,limit=100000):
    if c.n>limit:raise ValueError('Order exceeds configured limit')
    m=math.isqrt(c.n)+int(math.isqrt(c.n)**2<c.n)
    table={};R=None
    for j in range(m):table.setdefault(R,j);R=add(c,R,c.G)
    stride=neg(c,mul(c,m,c.G));gamma=Q;log=[f'm=ceil(sqrt(n))={m}',f'baby table entries={len(table)}']
    for i in range(m+1):
        if gamma in table:
            d=(i*m+table[gamma])%c.n
            if mul(c,d,c.G)==Q:
                log.append(f'collision: i={i}, j={table[gamma]}, d=(i*m+j) mod n={d}')
                return d,m+i+1,log
        gamma=add(c,gamma,stride)
    return None,m+m+1,log

def rho(c,Q,restarts=24,max_steps=200000,seed=42):
    """Pollard rho for any n; solves collision congruence even if gcd != 1."""
    if c.n>100000:raise ValueError('Toy subgroup order must be <= 100000')
    rng=random.Random(seed);operations=0;log=[]
    def step(state):
        P,a,b=state
        # 3-way partition based on x coordinate, deterministic for a run
        v=(P[0] if P else 0)%3
        if v==0:return add(c,P,c.G),(a+1)%c.n,b
        if v==1:return add(c,P,Q),a,(b+1)%c.n
        return add(c,P,P),(2*a)%c.n,(2*b)%c.n
    for attempt in range(1,restarts+1):
        a=rng.randrange(c.n);b=rng.randrange(c.n)
        start=(add(c,mul(c,a,c.G),mul(c,b,Q)),a,b)
        slow=start;fast=start
        for t in range(1,min(max_steps,max(100,10*c.n))+1):
            slow=step(slow);fast=step(step(fast));operations+=3
            if slow[0]!=fast[0]:continue
            # a1 G+b1 Q = a2 G+b2 Q -> (b2-b1)d = a1-a2 (mod n)
            u=(fast[2]-slow[2])%c.n;v=(slow[1]-fast[1])%c.n
            g=math.gcd(u,c.n)
            log.append(f'attempt={attempt}, collision at iteration={t}, gcd={g}')
            if v%g:break
            if u==0:break
            modulus=c.n//g
            if modulus==1:break
            root=(v//g*pow(u//g,-1,modulus))%modulus
            for j in range(g):
                d=root+j*modulus
                if mul(c,d,c.G)==Q:
                    log.append(f'solved congruence {u}*d = {v} (mod {c.n}); d={d}')
                    return d,operations,log
            break
    return None,operations,log+['No solution in allocated restarts; retry with another seed.']

def crt(congruences):
    x=0;M=1
    for a,m in congruences:
        if math.gcd(M,m)!=1:raise ValueError('CRT moduli must be coprime')
        x+=M*((a-x)*pow(M,-1,m)%m);M*=m;x%=M
    return x,M

def pohlig_hellman(c,Q,limit=100000):
    if c.n>limit:raise ValueError('Order exceeds configured limit')
    facts=factor(c.n);log=[f'n={c.n}; factorization={facts}'];congruences=[];ops=0
    for q,e in facts.items():
        x=0
        H=mul(c,c.n//q,c.G)
        for j in range(e):
            scale=c.n//(q**(j+1))
            target=mul(c,scale,add(c,Q,neg(c,mul(c,x,c.G))))
            R=None;digit=None
            for t in range(q):
                ops+=1
                if R==target:digit=t;break
                R=add(c,R,H)
            if digit is None:return None,ops,log+[f'Failed digit for {q}^{j}']
            x+=digit*q**j
            log.append(f'prime={q}, digit j={j}, digit={digit}, partial x={x}')
        congruences.append((x,q**e))
    d,N=crt(congruences)
    log.append(f'CRT {congruences} -> d={d} (mod {N})')
    return (d if mul(c,d,c.G)==Q else None),ops,log

def bounded_brute(c,Q,bound=10000,work=MAX_WORK):
    """Search [0,bound], stopping after at most work candidate checks."""
    R=None
    attempts=min(bound+1,work)
    for d in range(attempts):
        if R==Q:return d,d+1,[f'Found d={d} in interval [0,{bound}]']
        R=add(c,R,c.G)
    return None,attempts,[f'Not found after {attempts} candidates (interval upper bound {bound}).',
                           'STOPPED BY WORK BUDGET' if attempts<bound+1 else 'Interval exhausted.']

def bounded_bsgs(c,Q,bound=10000,work=MAX_WORK):
    """Interval BSGS: refuse allocation above the configured operation budget."""
    m=math.isqrt(bound)+int(math.isqrt(bound)**2<bound)
    giant=(bound//m)+2
    if m+giant>work:
        return None,0,[f'Estimated BSGS cost: {m} baby steps + {giant} giant steps.',
                       f'Exceeds configured work budget {work}; no allocation attempted.',
                       'Reduce interval or raise the budget on a sufficiently powerful machine.']
    baby={};R=None
    for j in range(m):baby.setdefault(R,j);R=add(c,R,c.G)
    step=neg(c,mul(c,m,c.G));T=Q
    for i in range(giant):
        if T in baby:
            d=i*m+baby[T]
            if d<=bound and mul(c,d,c.G)==Q:return d,m+i+1,[f'BSGS collision i={i}, j={baby[T]}, bound={bound}']
        T=add(c,T,step)
    return None,m+giant,[f'No discrete log in [0,{bound}].']

def bounded_rho(c,Q,bound=10000,restarts=8,seed=42,work=MAX_WORK):
    """Pollard kangaroo: bounded-interval variant, with a finite work budget."""
    rng=random.Random(seed)
    # Limit jump-table size; large intervals may not be solvable within the budget.
    jump_count=min(32,max(1,(math.isqrt(bound).bit_length())))
    jump_sizes=[1<<j for j in range(jump_count)]
    jumps=[mul(c,j,c.G) for j in jump_sizes]
    def walk(P,dist):
        ix=(P[0] if P else 0)%len(jumps)
        return add(c,P,jumps[ix]),dist+jump_sizes[ix]
    total=0;log=[f'Pollard kangaroo on [0,{bound}], operation budget={work}.',
                 'This is an interval algorithm, not full-order Pollard rho.']
    for attempt in range(restarts):
        remaining=work-total
        if remaining<2:break
        budget=min(remaining,max(2000,30*math.isqrt(bound+1)))
        offset=rng.randrange(min(bound+1,1000))
        tame=mul(c,bound+offset,c.G);td=bound+offset
        table={}
        for _ in range(budget//2):
            table.setdefault(tame,td)
            tame,td=walk(tame,td);total+=1
        wild=Q;wd=0
        for _ in range(budget-budget//2):
            if wild in table:
                d=table[wild]-wd
                if 0<=d<=bound and mul(c,d,c.G)==Q:
                    return d,total,log+[f'Kangaroo collision; d={d}; restart={attempt+1}']
            wild,wd=walk(wild,wd);total+=1
    return None,total,log+['No verified collision within work budget; result is inconclusive.']

def bounded_pohlig(c,Q,bound=10000):
    # PH fundamentally uses the FULL group order, not a guessed weak-key bound.
    # For large prime n there is no small prime-power decomposition to exploit.
    if c.n<=MAX_ATTACK_ORDER:return pohlig_hellman(c,Q)
    factors={}
    remainder=c.n
    for q in (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257):
        while remainder%q==0:factors[q]=factors.get(q,0)+1;remainder//=q
    log=[f'Pohlig–Hellman: trial division for small prime factors; found={factors}; residual factor has {remainder.bit_length()} bits.',
         'Full PH cannot finish without solving DLP in the large residual-order subgroup.',
         'Bounded-key search is not Pohlig–Hellman; use tabs 01–03 to recover deliberately small d.']
    return None,len(factors),log

def fmt(P):return 'O (infinity)' if P is None else f'({P[0]}, {P[1]})'

if '--self-test' not in sys.argv:
    from PyQt6.QtWidgets import (QApplication,QWidget,QMainWindow,QVBoxLayout,QHBoxLayout,QFormLayout,
        QTabWidget,QLabel,QPushButton,QComboBox,QLineEdit,QPlainTextEdit,QGroupBox,QMessageBox)

    class Lab(QMainWindow):
        def __init__(self):
            super().__init__();self.setWindowTitle('Week 08 — ECDLP Mathematical Cryptanalysis | 01–04');self.resize(1120,830)
            self.tabs=QTabWidget();self.setCentralWidget(self.tabs)
            self.controls=[]
            self.shared_private_scalar='3'  # valid initial scalar for every bundled toy curve; user editable
            self._syncing_scalar=False
            for i,(name,desc) in enumerate([
                ('01 · Exhaustive Search','Enumerate [d]G for d=0,...,n−1 until Q is found. O(n) time, O(1) memory.'),
                ('02 · Baby-Step Giant-Step','Shanks algorithm: O(sqrt(n)) group operations and O(sqrt(n)) memory.'),
                ('03 · Pollard Rho','Toy: Pollard rho; historical: Pollard kangaroo bounded-interval random walk.'),
                ('04 · Pohlig–Hellman','Factor n, recover discrete-log digits modulo prime powers, then combine using CRT.')]):
                self.build_tab(i,name,desc)
            self.statusBar().showMessage('All curves executable with budgets; historical SEC curves use bounded-key experiments (PH reports feasibility).')

        def sync_private_scalar(self,value,source):
            if self._syncing_scalar:return
            self.shared_private_scalar=value
            self._syncing_scalar=True
            try:
                for control in self.controls:
                    target=control[1]
                    if target is not source and target.text()!=value:target.setText(value)
            finally:
                self._syncing_scalar=False

        def build_tab(self,i,name,desc):
            w=QWidget();v=QVBoxLayout(w);v.addWidget(QLabel(desc))
            group=QGroupBox('Toy curves / historical SEC named curves and ECDLP challenge');form=QFormLayout(group)
            preset=QComboBox();preset.addItems([t[0] for t in PRESETS]);preset.addItems(['SEC (historical): '+x for x in HISTORICAL_CURVES]);form.addRow('Preset',preset)
            coords=QHBoxLayout();fields=[]
            for label,default in zip(('p','a','b','Gx','Gy'),PRESETS[0][1:]):
                edit=QLineEdit(str(default));edit.setMaximumWidth(125);coords.addWidget(QLabel(label));coords.addWidget(edit);fields.append(edit)
            form.addRow('Prime-field parameters',coords)
            private=QLineEdit(self.shared_private_scalar);private.setPlaceholderText('Enter integer d, e.g. 3 or 0x03');form.addRow('Private scalar d (editable; shared across tabs)',private)
            private.setToolTip('Enter your own private scalar; it is synchronized across all four attack tabs. Generate target Q after changing d.')
            private.textChanged.connect(lambda value, source=private: self.sync_private_scalar(value,source))
            bound_edit=QLineEdit('1000000');form.addRow('Search interval maximum B (historical curves; user-defined)',bound_edit)
            budget_edit=QLineEdit('200000');form.addRow('Maximum search attempts / attack work (user-defined)',budget_edit)
            bound_edit.setToolTip('Decimal or 0x hex; may be as large as n-1. This is an interval, not a promise to search all values.')
            budget_edit.setToolTip('Any positive integer, decimal or 0x hexadecimal. No built-in upper cap. High values can consume substantial time or memory.')
            pub=QLineEdit();pub.setPlaceholderText('Generate target or enter x,y (or O)');form.addRow('Target Q=[d]G',pub)
            info=QLabel();info.setWordWrap(True);form.addRow('Curve information',info)
            v.addWidget(group)
            buttons=QHBoxLayout();generate=QPushButton('Generate target Q');run=QPushButton('Run attack');clear=QPushButton('Clear log');copy=QPushButton('Copy log')
            for b in (generate,run,clear,copy):buttons.addWidget(b)
            v.addLayout(buttons)
            log=QPlainTextEdit();log.setReadOnly(True);log.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap);v.addWidget(log,1)
            self.tabs.addTab(w,name);self.controls.append((fields,private,pub,info,log))
            def selected(idx):
                if idx < len(PRESETS):
                    for edit,value in zip(fields,PRESETS[idx][1:]):edit.setText(str(value))
                    for edit in fields:edit.setReadOnly(False)
                    info.setText('Toy curve: attacks can run.');pub.clear()
                    # Preserve a user-entered d when valid; otherwise reset to a valid default.
                    try:
                        selected_curve=make_curve(*PRESETS[idx][1:])
                        current_d=int(private.text().strip(),0)
                        if not 1 <= current_d < selected_curve.n:
                            private.setText(str(min(3,selected_curve.n-1)))
                    except (ValueError,TypeError):
                        private.setText('1')
                else:
                    for edit in fields:edit.setReadOnly(True)
                    try:
                        c,h=openssl_named_curve(HISTORICAL_CURVES[idx-len(PRESETS)])
                        for edit,value in zip(fields,(c.p,c.a,c.b,*c.G)):edit.setText(str(value))
                        info.setText(f'Historical named curve {c.name}; field={c.p.bit_length()} bits; subgroup order={c.n.bit_length()} bits; cofactor={h}.\nAttacks enabled with work budgets. Select B and a separate work budget; a large B does not imply a feasible attack. Full ECDLP remains infeasible.')
                        log.appendPlainText(f'Loaded {c.name} via OpenSSL; n={c.n}; h={h}; [n]G=O verified.\n')
                    except Exception as exc:
                        info.setText(f'OpenSSL unavailable / curve unsupported: {exc}')
                    pub.clear()
            preset.currentIndexChanged.connect(selected)
            def get_curve():
                if preset.currentIndex() >= len(PRESETS):
                    return openssl_named_curve(HISTORICAL_CURVES[preset.currentIndex()-len(PRESETS)])[0]
                vals=[int(f.text().strip(),0) for f in fields]
                return make_curve(*vals)
            def generate_target():
                try:
                    c=get_curve();d=int(private.text().strip(),0)
                    if not 1 <= d < c.n:raise ValueError(f'Private scalar must satisfy 1 <= d < n (n={c.n})')
                    Q=mul(c,d,c.G);pub.setText('O' if Q is None else f'{Q[0]},{Q[1]}')
                    if c.n<=MAX_ATTACK_ORDER:
                        total=len(enumerate_points(c.p,c.a,c.b))+1
                        info.setText(f'E(F_{c.p}): #E={total}; G={fmt(c.G)}; ord(G)=n={c.n}; cofactor h={total//c.n}; n factors={factor(c.n)}')
                    else:
                        info.setText(f'{c.name}: p={c.p.bit_length()} bits, n={c.n.bit_length()} bits. Search bound B and operation budget are separate. Recovery requires sufficient work and d <= B.')
                    log.appendPlainText(f'Challenge: user-selected d={d}; Q=[d]G={fmt(Q)}; n={c.n}\n')
                except Exception as ex:QMessageBox.warning(w,'Invalid curve / key',str(ex))
            generate.clicked.connect(generate_target)
            def run_attack():
                try:
                    c=get_curve()
                    large=c.n>MAX_ATTACK_ORDER
                    bound=int(bound_edit.text().strip(),0)
                    if large and not 1 <= bound < c.n:raise ValueError(f'Interval bound must satisfy 1 <= B < n (n={c.n})')
                    work=int(budget_edit.text().strip(),0)
                    if work < 1:raise ValueError('Maximum search attempts / attack work must be a positive integer')
                    if work > 2000000:
                        choice=QMessageBox.question(w,'Large computational workload',
                            f'You requested up to {work:,} attack operations.\n'
                            'The GUI may become unresponsive and BSGS may use substantial memory.\n'
                            'Continue with your selected limit?',
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                            QMessageBox.StandardButton.No)
                        if choice != QMessageBox.StandardButton.Yes:return
                    raw=pub.text().strip()
                    if not raw:raise ValueError('Generate or enter target Q first')
                    Q=None if raw.upper() in ('O','INF','INFINITY') else tuple(int(z.strip(),0) for z in raw.strip('()').split(','))
                    if Q is not None and len(Q)!=2:raise ValueError('Use x,y coordinates')
                    if not on_curve(c,Q):raise ValueError('Q is not on E(F_p)')
                    if mul(c,c.n,Q) is not None:raise ValueError('Q is not in the subgroup generated by G')
                    start=time.perf_counter()
                    if i==0:result,ops,lines=(bounded_brute(c,Q,bound,work) if large else brute(c,Q))
                    elif i==1:result,ops,lines=(bounded_bsgs(c,Q,bound,work) if large else bsgs(c,Q))
                    elif i==2:result,ops,lines=(bounded_rho(c,Q,bound,work=work) if large else rho(c,Q))
                    else:result,ops,lines=(bounded_pohlig(c,Q,bound) if large else pohlig_hellman(c,Q))
                    elapsed=time.perf_counter()-start
                    verified=result is not None and mul(c,result,c.G)==Q
                    header=f'\n=== {name} ===\nCurve p={c.p}, a={c.a}, b={c.b}, G={fmt(c.G)}, n={c.n}\nTarget Q={fmt(Q)}\n'
                    output='\n'.join(lines)
                    footer=f'\nRecovered d={result}; verified={verified}; operation count (algorithm-specific)={ops}; elapsed={elapsed:.6f} s\n'
                    if large:footer+='Historical SEC experiment uses bounded work, not a break of the full curve ECDLP.\n'
                    log.appendPlainText(header+output+footer)
                    self.statusBar().showMessage(f'{name}: verified={verified}; recovered d={result}; {elapsed:.5f}s')
                except Exception as ex:QMessageBox.warning(w,'Attack error',str(ex))
            run.clicked.connect(run_attack);clear.clicked.connect(log.clear)
            copy.clicked.connect(lambda:QApplication.clipboard().setText(log.toPlainText()))
            generate_target()

def self_test():
    for name in HISTORICAL_CURVES:
        try:
            c,h=openssl_named_curve(name)
            assert mul(c,c.n,c.G) is None
            Q=mul(c,37,c.G)
            for fn in (bounded_brute,bounded_bsgs,bounded_rho):
                d,_,_=fn(c,Q,200)
                assert d==37,(name,fn.__name__,d)
            result,_,_=bounded_pohlig(c,Q,200)
            assert result is None
            print(f'PASS SEC {name}: p_bits={c.p.bit_length()}, n_bits={c.n.bit_length()}, cofactor={h}')
        except ValueError as exc:
            print(f'SKIP SEC {name}: {exc}')
    for label,p,a,b,x,y in PRESETS:
        c=make_curve(p,a,b,x,y)
        for d in range(c.n):
            Q=mul(c,d,c.G)
            for fn in (brute,bsgs,rho,pohlig_hellman):
                answer,_,_=fn(c,Q)
                if answer!=d:raise AssertionError((label,d,fn.__name__,answer))
        print(f'PASS {label}; n={c.n}; all {c.n} scalars; 4 attacks')

if __name__=='__main__':
    if '--self-test' in sys.argv:self_test()
    else:
        app=QApplication(sys.argv);window=Lab();window.show();sys.exit(app.exec())
