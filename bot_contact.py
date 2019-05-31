import json, sys, cryptutil, base64

data = open(sys.argv[1]).read().split('\n')

assert data[0].startswith('BOT_KEY = ')
bot_key = eval(data[0][10:])
bot_id = cryptutil.hash(cryptutil.import_key(bot_key).publickey())

if '--devel' in sys.argv:
    path = repr(os.path.abspath(sys.argv[1]))
    data = ('exec(compile(open('+path+', "rb").read(), '+path+', "exec"))').encode('utf-8')
else:
    data = open(sys.argv[1], 'rb').read()

sock = 'python://'+''.join(base64.b64encode(data).decode('ascii').split())

print(json.dumps({
    'peers': {cryptutil.export_key(cryptutil.import_key(bot_key).publickey()): sys.argv[2]},
    'trusted': [bot_id],
    'sockets': [sock],
    'relays': {},
    'exclusive': {bot_id: sock}
}))
