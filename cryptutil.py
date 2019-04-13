import Crypto.PublicKey.RSA as rsa, base64, hashlib, os, sys

sys.setrecursionlimit(max(sys.getrecursionlimit(), 10000))

def import_key(s):
    return rsa.importKey(base64.b64decode(s.encode('ascii')))

def import_binary_key(s):
    return rsa.importKey(s)

def export_key(key):
    return ''.join(base64.b64encode(key.exportKey('DER')).decode('ascii').split())

def hash(x):
    h = hashlib.sha256()
    h.update(x.exportKey('DER'))
    return h.hexdigest()

def _fast_pow(a, b, n):
    if b == 0:
        return 1
    elif b % 2:
        return (a * _fast_pow(a, b-1, n)) % n
    else:
        return _fast_pow((a * a) % n, b // 2, n)

def _xxcrypt(data, key, which):
    n = int.from_bytes(data, 'big')
    assert n < key.n
    return _fast_pow(n, getattr(key, which), key.n).to_bytes(128, 'big')

def urandom_nozero():
    ans = b'\0'
    while not ans[0]: ans = os.urandom(16)
    return ans

def encrypt(data, key, which='d'):
    h = hashlib.sha256()
    h.update(data)
    data += h.digest()
    ans = b''
    for i in range(0, len(data), 111):
        chunk = urandom_nozero()+data[i:i+111]
        ans += _xxcrypt(chunk, key, which)
    return ans

def decrypt(data, key, which='e'):
    ans = b''
    for i in range(0, len(data), 128):
        try: chunk = _xxcrypt(data[i:i+128], key, which)
        except: return None
        while not chunk[0]: chunk = chunk[1:]
        ans += chunk[16:]
    h = hashlib.sha256()
    h.update(ans[:-32])
    if h.digest() != ans[-32:]:
        return None
    return ans[:-32]

def sign(data, key):
    h = hashlib.sha256()
    h.update(data)
    return data + encrypt(h.digest(), key)

def check_sign(data, key):
    data0 = data[:-128]
    h = hashlib.sha256()
    h.update(data0)
    sign = data[-128:]
    return h.digest() == decrypt(sign, key)
