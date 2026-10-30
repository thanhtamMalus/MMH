#!/usr/bin/env python3
"""ChaCha20-Poly1305 nonce-reuse confidentiality recovery. No key; no tag verification."""
import argparse
from pathlib import Path
from kpa_common import parse_spec, recover_keystream, recover_plaintext, save_bytes, write_target_output, prompt_spec
TAG_LEN=16

def split_ciphertext_tag(blob: bytes):
    if len(blob)<TAG_LEN: raise ValueError('Combined ciphertext||tag is shorter than 16 bytes.')
    return blob[:-TAG_LEN],blob[-TAG_LEN:]

def interactive():
    print('='*82); print('CHACHA20-POLY1305 NONCE-REUSE KNOWN-PLAINTEXT ATTACK'); print('CONFIDENTIALITY RECOVERY ONLY — NO KEY — NO TAG VERIFICATION'); print('='*82)
    combined=input('Are ciphertext inputs ciphertext||16-byte-tag? [y/N]: ').strip().lower()=='y'
    p1=parse_spec(prompt_spec('Known plaintext P1')); raw1=parse_spec(prompt_spec('Matching C1'+(' || tag' if combined else '')))
    if combined:
        c1,tag1=split_ciphertext_tag(raw1); print(f'Known tag1: {tag1.hex()} [NOT USED / NOT VERIFIED]')
    else: c1=raw1
    z=recover_keystream(p1,c1); print(f'\nRecovered payload keystream: {len(z)} bytes\nZpayload(hex) = {z.hex()}')
    ks=input('Save payload keystream binary [keystream_aead.bin / empty=no]? ').strip()
    if ks: print(f'[+] Keystream saved: {save_bytes(ks,z).resolve()}')
    mode=input('Recovered output [text/hex/base64/file] (text): ').strip().lower() or 'text'
    outdir=(input('Output directory [.]: ').strip() or '.') if mode=='file' else None
    count=int(input('Number of targets C2,C3,... [2]: ') or '2')
    for idx in range(2,2+count):
        raw=parse_spec(prompt_spec(f'Target C{idx}'+(' || tag' if combined else '')))
        if combined:
            c,tag=split_ciphertext_tag(raw); print(f'Tag{idx}: {tag.hex()} [NOT VERIFIED]')
        else: c=raw
        p=recover_plaintext(c,z); print(f'\n[+] P{idx}: recovered {len(p)}/{len(c)} payload bytes'); print(write_target_output(p,idx,mode,outdir)); print('[!] Authentication status: UNKNOWN')
        if len(c)>len(z): print(f'[!] {len(c)-len(z)} trailing byte(s) remain unknown.')

def main():
    ap=argparse.ArgumentParser(description='Recover ChaCha20-Poly1305 payload plaintext under (key,nonce) reuse.')
    ap.add_argument('--known-p',help='text:..., hex:..., base64:..., or file:path'); ap.add_argument('--known-c',help='Payload or ciphertext||tag')
    ap.add_argument('--target',action='append',default=[]); ap.add_argument('--combined',action='store_true',help='Inputs are ciphertext||16-byte tag')
    ap.add_argument('--save-keystream',help='Save recovered payload keystream as raw binary'); ap.add_argument('--output',choices=['text','hex','base64','file'],default='text'); ap.add_argument('--output-dir',default='recovered'); ap.add_argument('--interactive',action='store_true')
    a=ap.parse_args()
    if a.interactive or not (a.known_p and a.known_c and a.target): interactive(); return
    p1,raw1=parse_spec(a.known_p),parse_spec(a.known_c)
    if a.combined:
        c1,tag1=split_ciphertext_tag(raw1); print(f'[*] Known tag1: {tag1.hex()} [NOT USED / NOT VERIFIED]')
    else: c1=raw1
    z=recover_keystream(p1,c1); print(f'[+] Recovered payload keystream: {len(z)} bytes\n    Zpayload(hex) = {z.hex()}')
    if a.save_keystream: print(f'[+] Keystream binary saved: {save_bytes(a.save_keystream,z)}')
    for idx,spec in enumerate(a.target,2):
        raw=parse_spec(spec)
        if a.combined:
            c,tag=split_ciphertext_tag(raw); print(f'\n[*] Tag{idx}: {tag.hex()} [NOT VERIFIED]')
        else: c=raw
        p=recover_plaintext(c,z); print(f'[+] P{idx}: recovered {len(p)}/{len(c)} payload bytes'); print(write_target_output(p,idx,a.output,a.output_dir)); print('[!] Authentication status: UNKNOWN')
        if len(c)>len(z): print(f'[!] {len(c)-len(z)} trailing byte(s) remain unknown.')
if __name__=='__main__': main()
