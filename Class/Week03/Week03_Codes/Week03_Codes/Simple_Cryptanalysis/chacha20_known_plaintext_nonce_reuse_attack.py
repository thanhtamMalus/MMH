#!/usr/bin/env python3
"""ChaCha20 known-plaintext attack under nonce/counter keystream reuse. No key input."""
import argparse
from pathlib import Path
from kpa_common import parse_spec, recover_keystream, recover_plaintext, save_bytes, write_target_output, prompt_spec

def interactive():
    print('='*80); print('CHACHA20 KNOWN-PLAINTEXT ATTACK UNDER NONCE/COUNTER REUSE'); print('NO SECRET KEY REQUIRED'); print('='*80)
    print('Required: same key + nonce + overlapping counter/byte positions.')
    p1=parse_spec(prompt_spec('Known plaintext P1')); c1=parse_spec(prompt_spec('Matching ciphertext C1'))
    z=recover_keystream(p1,c1); print(f'\nRecovered keystream segment: {len(z)} bytes\nZ(hex) = {z.hex()}')
    ks=input('Save keystream binary [keystream_chacha20.bin / empty=no]? ').strip()
    if ks: print(f'[+] Keystream saved: {save_bytes(ks,z).resolve()}')
    mode=input('Recovered output [text/hex/base64/file] (text): ').strip().lower() or 'text'
    outdir=(input('Output directory [.]: ').strip() or '.') if mode=='file' else None
    count=int(input('Number of targets C2,C3,... [2]: ') or '2')
    for idx in range(2,2+count):
        c=parse_spec(prompt_spec(f'Target ciphertext C{idx}')); p=recover_plaintext(c,z)
        print(f'\n[+] P{idx}: recovered {len(p)}/{len(c)} bytes'); print(write_target_output(p,idx,mode,outdir))
        if len(c)>len(z): print(f'[!] {len(c)-len(z)} trailing byte(s) remain unknown.')

def main():
    ap=argparse.ArgumentParser(description='Recover ChaCha20 plaintext bytes from a known P,C pair when the keystream repeats.')
    ap.add_argument('--known-p',help='text:..., hex:..., base64:..., or file:path'); ap.add_argument('--known-c',help='text:..., hex:..., base64:..., or file:path')
    ap.add_argument('--target',action='append',default=[]); ap.add_argument('--save-keystream',help='Save recovered keystream as raw binary')
    ap.add_argument('--output',choices=['text','hex','base64','file'],default='text'); ap.add_argument('--output-dir',default='recovered')
    ap.add_argument('--known-nonce',help='Metadata check only; not used to derive Z'); ap.add_argument('--known-counter',type=int,help='Metadata check only')
    ap.add_argument('--target-nonce',action='append',default=[]); ap.add_argument('--target-counter',action='append',type=int,default=[])
    ap.add_argument('--force',action='store_true'); ap.add_argument('--interactive',action='store_true'); a=ap.parse_args()
    if a.interactive or not (a.known_p and a.known_c and a.target): interactive(); return
    p1,c1=parse_spec(a.known_p),parse_spec(a.known_c); z=recover_keystream(p1,c1)
    print(f'[+] Recovered keystream: {len(z)} bytes\n    Z(hex) = {z.hex()}')
    if a.save_keystream: print(f'[+] Keystream binary saved: {save_bytes(a.save_keystream,z)}')
    for j,spec in enumerate(a.target):
        idx=j+2; problems=[]
        if j<len(a.target_nonce) and a.known_nonce and a.target_nonce[j].lower()!=a.known_nonce.lower(): problems.append('nonce differs')
        if j<len(a.target_counter) and a.known_counter is not None and a.target_counter[j]!=a.known_counter: problems.append('counter differs')
        if problems and not a.force: print(f'\n[-] C{idx}: not attacked ({", ".join(problems)}).'); continue
        c=parse_spec(spec); p=recover_plaintext(c,z)
        print(f'\n[+] P{idx}: recovered {len(p)}/{len(c)} bytes'); print(write_target_output(p,idx,a.output,a.output_dir))
        if len(c)>len(z): print(f'[!] {len(c)-len(z)} trailing byte(s) remain unknown.')
if __name__=='__main__': main()
