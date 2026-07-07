# XXTEA Tool

A faithful Python port of the XXTEA decrypt/encrypt 
Supports decrypting base64‑encoded XXTEA ciphertext and encrypting plaintext,
with input from a **file**, a **URL (http/https)**, or **pasted text**.

> ⚠️ This is a port of a specific XXTEA implementation that uses the magic
> constant `DELTA = -1638454863` (not the canonical `0x9E3779B9`).
---

## Features

- 🔓 **Decrypt** base64 XXTEA strings → plaintext
- 🔒 **Encrypt** plaintext → base64 XXTEA strings
- 🌐 Input from **file path**, **URL**, or **direct paste**
- 💾 Output saved to the **current working directory**
- 🧪 Built‑in **self‑test** to verify correctness
- 🔑 Key is UTF‑8 encoded and zero‑padded/truncated to 16 bytes 

---

## Installation

Requires Python 3.6+ (uses only the standard library).

```bash
git clone https://github.com/hamadax2/xxtea.git
cd xxtea
Usage
----------
Decrypt

# From a file
python3 xxtea_tool.py decrypt dnslite.txt -k "key"

# From a URL
python3 xxtea_tool.py decrypt https://example.com/encrypted.txt -k "key"

# From pasted base64 text
python3 xxtea_tool.py decrypt "aPEX2ezxffVM5V4OGsYOhNmcmSzGYNY6..." -k "key"
____________
Encrypt
# From pasted text
python3 xxtea_tool.py encrypt "some secret text" -k "myKey123"

# From a file
python3 xxtea_tool.py encrypt plain.txt -k "myKey123"
