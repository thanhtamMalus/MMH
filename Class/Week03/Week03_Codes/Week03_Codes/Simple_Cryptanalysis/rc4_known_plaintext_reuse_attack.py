#!/usr/bin/env python3
"""Known-plaintext attack on raw RC4 under keystream reuse. No secret key input."""
import argparse
from pathlib import Path
from kpa_common import parse_spec, recover_keystream, recover_plaintext, save_bytes, write_target_output, prompt_spec

def interactive():
    print('='*76); print('RC4 KNOWN-PLAINTEXT / KEYSTREAM-REUSE ATTACK'); print('NO SECRET KEY REQUIRED'); print('='*76)
    print('Assumption: raw RC4 was restarted at byte 0 with the SAME key.')
    p1 = parse_spec(prompt_spec('Known plaintext P1'))
    c1 = parse_spec(prompt_spec('Matching ciphertext C1'))
    z = recover_keystream(p1, c1)
    print(f'\nRecovered keystream segment: {len(z)} bytes\nZ(hex) = {z.hex()}')
    ks = input('Save keystream binary [keystream.bin / empty=no]? ').strip()
    if ks: print(f'[+] Keystream saved: {save_bytes(ks,z).resolve()}')
    mode = input('Recovered output [text/hex/base64/file] (text): ').strip().lower() or 'text'
    outdir = (input('Output directory [.]: ').strip() or '.') if mode == 'file' else None
    count = int(input('Number of targets C2,C3,... [2]: ') or '2')
    for idx in range(2,2+count):
        c = parse_spec(prompt_spec(f'Target ciphertext C{idx}'))
        p = recover_plaintext(c,z)
        print(f'\n[+] P{idx}: recovered {len(p)}/{len(c)} bytes')
        print(write_target_output(p,idx,mode,outdir))
        if len(c)>len(z): print(f'[!] {len(c)-len(z)} trailing byte(s) remain unknown.')

def main():
    ap=argparse.ArgumentParser(description='Recover reused raw-RC4 keystream from one known P,C pair; no key input.')
    ap.add_argument('--known-p',help='text:..., hex:..., base64:..., or file:path')
    ap.add_argument('--known-c',help='text:..., hex:..., base64:..., or file:path')
    ap.add_argument('--target',action='append',default=[],help='Target C2/C3/...; repeat as needed')
    ap.add_argument('--save-keystream',help='Save recovered keystream as raw binary')
    ap.add_argument('--output',choices=['text','hex','base64','file'],default='text')
    ap.add_argument('--output-dir',default='recovered')
    ap.add_argument('--interactive',action='store_true')
    a=ap.parse_args()
    if a.interactive or not (a.known_p and a.known_c and a.target): interactive(); return
    p1,c1=parse_spec(a.known_p),parse_spec(a.known_c); z=recover_keystream(p1,c1)
    print(f'[+] Recovered keystream: {len(z)} bytes\n    Z(hex) = {z.hex()}')
    if a.save_keystream: print(f'[+] Keystream binary saved: {save_bytes(a.save_keystream,z)}')
    for idx,spec in enumerate(a.target,2):
        c=parse_spec(spec); p=recover_plaintext(c,z)
        print(f'\n[+] P{idx}: recovered {len(p)}/{len(c)} bytes')
        print(write_target_output(p,idx,a.output,a.output_dir))
        if len(c)>len(z): print(f'[!] {len(c)-len(z)} trailing byte(s) remain unknown.')
if __name__=='__main__': main()
