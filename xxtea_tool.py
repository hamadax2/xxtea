#!/usr/bin/env python3
import base64
import sys
import os
import json
import argparse

try:
    import urllib.request
    _HAS_URLLIB = True
except Exception:
    _HAS_URLLIB = False

# Same magic constant as xxtea.java: i3 = i * -1638454863
DELTA = -1638454863

# ---------------------------------------------------------------------------
# Core XXTEA port (unchanged from the verified Java logic)
# ---------------------------------------------------------------------------

def u32(x):
    return x & 0xFFFFFFFF

def mx(z, y, _sum, p, e, key):
    z &= 0xFFFFFFFF
    y &= 0xFFFFFFFF
    _sum &= 0xFFFFFFFF
    p &= 0xFFFFFFFF
    e &= 0xFFFFFFFF
    part1 = ((z ^ y) + (key[((p & 3) ^ e) & 3] ^ _sum)) & 0xFFFFFFFF
    part2 = ((_sum >> 5) ^ (y << 2)) & 0xFFFFFFFF
    part3 = ((y >> 3) ^ (_sum << 4)) & 0xFFFFFFFF
    return (part1 ^ ((part2 + part3) & 0xFFFFFFFF)) & 0xFFFFFFFF

def bytes_to_ints(data, include_length):
    n = len(data)
    words = n >> 2 if (n & 3) == 0 else (n >> 2) + 1
    if include_length:
        out = [0] * (words + 1)
        out[words] = n
    else:
        out = [0] * words
    for i in range(n):
        out[i >> 2] |= (data[i] & 0xFF) << ((i & 3) << 3)
    return out

def ints_to_bytes(ints, use_length):
    n = len(ints)
    total = n << 2
    if use_length:
        last = ints[n - 1]
        if (total - 7) <= last <= (total - 4):
            length = last
        else:
            return None
    else:
        length = total
    out = bytearray(length)
    for i in range(length):
        out[i] = (ints[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)

def _prepare_key(key):
    if len(key) != 16:
        padded = bytearray(16)
        n = min(len(key), 16)
        padded[:n] = key[:n]
        key = bytes(padded)
    return bytes_to_ints(key, False)

def xxtea_decrypt(ciphertext, key):
    k = _prepare_key(key)
    v = bytes_to_ints(ciphertext, False)
    n = len(v)
    if n > 1:
        rounds = (52 // n) + 6
        y = v[0]
        _sum = u32(rounds * DELTA)
        for _ in range(rounds):
            e = (_sum >> 2) & 3
            z = y
            p = n - 1
            while p > 0:
                z = u32(v[p] - mx(_sum, z, v[p - 1], p, e, k))
                v[p] = z
                p -= 1
            y = u32(v[0] - mx(_sum, z, v[n - 1], 0, e, k))
            v[0] = y
            _sum = u32(_sum - DELTA)
    return ints_to_bytes(v, True)

def xxtea_encrypt(plaintext, key):
    if len(plaintext) == 0:
        return plaintext
    k = _prepare_key(key)
    v = bytes_to_ints(plaintext, True)
    n = len(v)
    n2 = n - 1
    if n2 >= 1:
        rounds = (52 // n) + 6
        z = v[n2]
        _sum = 0
        i3 = rounds
        while True:
            i4 = i3 - 1
            if i3 <= 0:
                break
            _sum = u32(DELTA + _sum)
            e = (_sum >> 2) & 3
            y = z
            z = 0
            p = 0
            while p < n2:
                p1 = p + 1
                y = u32(v[p] + mx(_sum, v[p1], y, p, e, k))
                v[p] = y
                p = p1
            z = u32(mx(_sum, v[0], y, n2, e, k) + v[n2])
            v[n2] = z
            i3 = i4
    return ints_to_bytes(v, False)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64_decode(s):
    s = s.strip()
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.b64decode(s)

def b64_encode(b):
    return base64.b64encode(b).decode('ascii')

def fetch_source(value):
    """Determine if `value` is a URL, a file path, or raw pasted text."""
    if _HAS_URLLIB and (value.startswith("http://") or value.startswith("https://")):
        print(f"[*] Fetching from URL: {value}")
        req = urllib.request.Request(value, headers={"User-Agent": "xxtea-tool/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode('utf-8', errors='replace')
    # Treat as file path if it exists, otherwise as pasted text
    if os.path.isfile(value):
        print(f"[*] Reading from file: {value}")
        with open(value, 'r', encoding='utf-8') as f:
            return f.read()
    print("[*] Using pasted text input")
    return value

def save(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(data)
    print(f"[+] Saved: {os.path.abspath(path)}")

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_decrypt(args):
    raw = fetch_source(args.input)
    ct = b64_decode(raw)
    pt = xxtea_decrypt(ct, args.key.encode('utf-8'))
    if pt is None:
        print("[-] Decryption returned null. Check key or data.")
        return 1
    try:
        text = pt.decode('utf-8')
    except UnicodeDecodeError:
        text = pt.decode('utf-8', errors='replace')
        print("[!] Output was not clean UTF-8 (wrong key?); saving with replacements")

    print("\n========== Decrypted String ==========")
    print(text)
    print("======================================\n")

    base = os.path.splitext(os.path.basename(args.input if os.path.isfile(args.input) else "data"))[0]
    save(os.path.join(os.getcwd(), "decrypted.txt"), text)
    save(os.path.join(os.getcwd(), "output.json"), json.dumps({"data": text}, ensure_ascii=False))
    return 0

def cmd_encrypt(args):
    raw = fetch_source(args.input)
    # Encrypt the UTF-8 bytes of the input text
    ct = xxtea_encrypt(raw.encode('utf-8'), args.key.encode('utf-8'))
    if ct is None:
        print("[-] Encryption failed.")
        return 1
    b64 = b64_encode(ct)

    print("\n========== Encrypted (Base64) ==========")
    print(b64)
    print("=========================================\n")

    save(os.path.join(os.getcwd(), "encrypted.b64"), b64)
    return 0

def cmd_selftest(args):
    key = b"...|..."
    pt = "Hello XXTEA! This is a test 12345.".encode('utf-8')
    ct = xxtea_encrypt(pt, key)
    pt2 = xxtea_decrypt(ct, key)
    assert pt2 == pt, "roundtrip failed!"
    print("[+] Self-test passed: encrypt/decrypt roundtrip OK with key b'...|...'")
    return 0

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="XXTEA encrypt/decrypt tool (port of xxtea.java)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser("decrypt", help="Decrypt a base64 XXTEA string")
    p_dec.add_argument("input", help="File path, URL (http/https), or pasted base64 text")
    p_dec.add_argument("-k", "--key", default="...|...", help="Encryption key (default: ...|...)")
    p_dec.set_defaults(func=cmd_decrypt)

    p_enc = sub.add_parser("encrypt", help="Encrypt text to base64 XXTEA")
    p_enc.add_argument("input", help="File path, URL (http/https), or pasted plaintext")
    p_enc.add_argument("-k", "--key", default="...|...", help="Encryption key (default: ...|...)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_test = sub.add_parser("selftest", help="Run encrypt/decrypt round-trip self-test")
    p_test.set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    sys.exit(args.func(args))

if __name__ == "__main__":
    main()