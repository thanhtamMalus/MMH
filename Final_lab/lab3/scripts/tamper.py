#!/usr/bin/env python3
"""Tamper envelope files for negative testing."""
import struct
import json
import sys
import os

def parse_envelope(data):
    """Parse envelope container returning (magic, version, header_len, header_json, payload)."""
    if len(data) < 9:
        raise ValueError("Envelope too short")
    
    magic = data[:4]
    if magic != b"RSAE":
        raise ValueError("Invalid magic: expected RSAE, got {}".format(magic))
    
    version = data[4]
    if version != 0x01:
        raise ValueError("Invalid version: expected 0x01, got 0x{:02x}".format(version))
    
    header_len = struct.unpack(">I", data[5:9])[0]
    
    if len(data) < 9 + header_len:
        raise ValueError("Data too short for declared header length")
    
    header_json = data[9:9+header_len].decode("utf-8")
    payload = data[9+header_len:]
    
    return magic, version, header_len, header_json, payload

def tamper(mode, in_path, out_path):
    """Tamper an envelope file according to the specified mode."""
    with open(in_path, "rb") as f:
        data = f.read()
    
    magic, version, header_len, header_json, payload = parse_envelope(data)
    
    if mode == "flip-payload":
        # Lật 1 bit trong payload
        if len(payload) == 0:
            raise ValueError("Empty payload cannot flip")
        byte_idx = 0
        bit_idx = 0
        # Flip the first bit of the first byte
        payload = bytearray(payload)
        payload[byte_idx] ^= (1 << bit_idx)
        payload = bytes(payload)
    
    elif mode == "flip-tag":
        # Lật 1 bit trong tag (trong header JSON)
        try:
            header = json.loads(header_json)
            if "tag" in header and len(header["tag"]) > 0:
                # Flip a bit in the base64 tag
                tag_bytes = header["tag"]
                # Decode base64, flip bit, re-encode
                import base64
                raw = base64.b64decode(tag_bytes + "==")
                if len(raw) > 0:
                    raw = bytearray(raw)
                    raw[0] ^= 1
                    header["tag"] = base64.b64encode(bytes(raw)).decode()
                    header_json = json.dumps(header)
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError("Failed to flip tag: {}".format(e))
    
    elif mode == "flip-wrapped-key":
        # Lật 1 bit trong wrapped_key (trong header JSON)
        try:
            header = json.loads(header_json)
            if "wrapped_key" in header and len(header["wrapped_key"]) > 0:
                import base64
                raw = base64.b64decode(header["wrapped_key"] + "==")
                if len(raw) > 0:
                    raw = bytearray(raw)
                    raw[0] ^= 1
                    header["wrapped_key"] = base64.b64encode(bytes(raw)).decode()
                    header_json = json.dumps(header)
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError("Failed to flip wrapped_key: {}".format(e))
    
    elif mode == "flip-header-iv":
        # Sửa iv trong header JSON
        try:
            header = json.loads(header_json)
            if "iv" in header:
                # Change iv to something different
                import base64
                # Generate random 12-byte IV and base64 encode it
                iv_bytes = os.urandom(12)
                header["iv"] = base64.b64encode(iv_bytes).decode()
                header_json = json.dumps(header)
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError("Failed to flip header IV: {}".format(e))
    
    elif mode == "change-modulus":
        # Đổi rsa_modulus trong header JSON
        try:
            header = json.loads(header_json)
            header["rsa_modulus"] = 4096 if header.get("rsa_modulus", 3072) == 3072 else 3072
            header_json = json.dumps(header)
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError("Failed to change modulus: {}".format(e))
    
    elif mode == "truncate":
        # Cắt cụt: làm ngắn payload
        payload = payload[:len(payload)//2]
    
    elif mode == "flip-direct":
        # Flip magic/version để làm mất magic
        payload = bytearray(payload)
        if len(payload) > 0:
            payload[0] ^= 1
        payload = bytes(payload)
    
    else:
        raise ValueError("Unknown tamper mode: {}".format(mode))
    
    # Reconstruct envelope
    new_header_bytes = header_json.encode("utf-8")
    new_header_len = len(new_header_bytes)
    
    # If header_len changed, we need to update the header_len field
    # But we keep the original header_len; the tampered header may have different length
    # This is intentional for testing detection
    
    new_data = magic + struct.pack("B", version) + struct.pack(">I", new_header_len) + new_header_bytes + payload
    
    with open(out_path, "wb") as f:
        f.write(new_data)
    
    print("Tampered file written to:", out_path)
    print("Mode:", mode)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: tamper.py --in <ct.bin> --out <ct_bad.bin> --mode {flip-payload,flip-tag,flip-wrapped-key,flip-header-iv,change-modulus,truncate,flip-direct}")
        sys.exit(1)
    
    args = sys.argv[1:]
    in_path = out_path = mode = None
    for i, arg in enumerate(args):
        if arg == "--in" and i + 1 < len(args):
            in_path = args[i + 1]
        elif arg == "--out" and i + 1 < len(args):
            out_path = args[i + 1]
        elif arg == "--mode" and i + 1 < len(args):
            mode = args[i + 1]
    
    if not all([in_path, out_path, mode]):
        print("Missing required arguments")
        sys.exit(1)
    
    tamper(mode, in_path, out_path)