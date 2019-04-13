import Crypto.PublicKey.RSA as rsa, json, base64

key = rsa.generate(1024)
print(json.dumps({"privkey": ''.join(base64.b64encode(key.exportKey('DER')).decode('ascii').split()), "peers": {}, "trusted": [], "relays": {}, "nicknames": {}, "sockets": []}))
