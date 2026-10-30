#!/usr/bin/env python3
from pathlib import Path
from kpa_common import recover_keystream, recover_plaintext

def xor(a,b): return bytes(x^y for x,y in zip(a,b))
z=bytes((i*37+11)%256 for i in range(4096))
p1=bytes(range(256))*8
p2=b'\x89PNG\r\n\x1a\n'+bytes((i*3)%256 for i in range(2040))
p3=b'%PDF-1.7\n'+bytes((255-i)%256 for i in range(2039))
c1,c2,c3=xor(p1,z),xor(p2,z),xor(p3,z)
rz=recover_keystream(p1,c1)
assert rz==z[:len(p1)]
assert recover_plaintext(c2,rz)==p2[:len(rz)]
assert recover_plaintext(c3,rz)==p3[:len(rz)]
tmp=Path('selftest_keystream.bin'); tmp.write_bytes(rz); assert tmp.read_bytes()==rz; tmp.unlink()
print('Binary keystream save/recovery self-test: PASS')
