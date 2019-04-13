import threading, queue, os, socket, sys, json, cryptutil

config = json.loads(open(sys.argv[1]).read())
privkey = cryptutil.import_key(config['privkey'])
pubkey = privkey.publickey()
msgq = queue.Queue()
peers = []

def update_config():
    with open(sys.argv[1], 'w') as file:
        print(json.dumps(config), file=file)

def peer_main(addr, q):
    a1, a2 = addr
    x = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    x.bind(a1)
    x.connect(a2)
    def sender_thread():
        while True:
            msg = q.get()
            x.sendall(msg)
    def receiver_thread():
        while True:
            try: msgq.put(x.recv(1048576))
            except: pass
    threading.Thread(target=sender_thread, daemon=True).start()
    threading.Thread(target=receiver_thread, daemon=True).start()

msg_cache = set()
self = cryptutil.hash(pubkey)
print('I\'m', self)

def receiver_loop():
    while True:
        msg = msgq.get()
        try: handle_packet(msg)
        except:
            sys.excepthook(*sys.exc_info())
            print('Note: caused by:', msg, file=sys.stderr)

def handle_packet(msg, is_relayed=False):
    idx, tp, dat = msg.split(b'\0', 2)
    if idx in msg_cache: return
    msg_cache.add(idx)
#   print(msg)
    if tp == b'EMSG':
        dat0 = cryptutil.decrypt(dat, privkey, 'd')
        if dat0 == None:
            send_pkt(msg)
            return #not for our eyes
        snd, dat = dat0[:-128].split(b'\0', 1)
        snd = snd.decode('ascii', 'replace')
        if snd not in config['peers']:
            tp0, dat0 = dat.split(b'\0', 1)
            if tp0 == b'MSG':
                idx1, rec1, snd1, tp1, dat1 = dat0.split(b'\0', 4)
                if tp1 == b'KEY':
#                   print('key is:', dat1)
                    key = cryptutil.import_binary_key(dat1)
#                   print('from %r: got key of %r'%(snd, cryptutil.hash(key)))
                    config['peers'][cryptutil.hash(key)] = cryptutil.export_key(key)
                    update_config()
            if snd not in config['peers']:
                send_msg(snd, b'NEEDKEY\0')
                return
        if not cryptutil.check_sign(dat0, cryptutil.import_key(config['peers'][snd])):
            print('Warning: invalid EMSG signature', file=sys.stderr)
            return
        else:
            msg_cache.remove(idx)
            return handle_packet(idx+b'\0'+dat, is_relayed)
    if tp == b'eMSG':
        rec, dat0 = dat.split(b'\0', 1)
        if rec != self.encode('ascii'):
            send_pkt(msg)
            return
        else:
            msg_cache.remove(idx)
            return handle_packet(idx+b'\0EMSG\0'+dat0, is_relayed)
    if tp == b'MSG' and not is_relayed:
        idx2, rec, dat0 = dat.split(b'\0', 2)
        if rec == self.encode('ascii'):
            handle_send_ack(idx2, dat0)
    if tp == b'MSG':
        idx2, rec, dat = dat.split(b'\0', 2)
        if rec == self.encode('ascii'):
            handle_incoming(idx2, dat)
        else:
            send_pkt(msg)
    elif tp == b'ACK':
        rec, idx2 = dat.split(b'\0', 1)
        if rec == self.encode('ascii'): 
            try: del sender_pool[idx2]
            except KeyError: pass
            print('> [%s] delivered'%idx2.decode('ascii', 'replace'))
        else:
            send_pkt(msg)
    else:
        print('Warning: dropping unrecognized packet:', msg, file=sys.stderr)

def handle_incoming(idx, dat):
#   print(dat)
    snd0, tp, dat = dat.split(b'\0', 2)
    snd = snd0.decode('ascii', 'replace')
    if tp == b'NEEDKEY':
        send_key_to(snd)
        return
    if tp == b'MSG':
        print('> [%s] %s wrote: %s'%(idx.decode('ascii', 'replace'), snd, dat))
    elif tp == b'KEY':
        key = cryptutil.import_binary_key(dat)
        config['peers'][cryptutil.hash(key)] = cryptutil.export_key(key)
    elif tp == b'RELAY':
        if snd in config['trusted']:
            tgt, msg = dat.split(b'\0', 1)
            tgt = tgt.decode('ascii', 'replace')
            send_msg(tgt, b'RELAYED\0'+msg)
        else:
            print('Warning: RELAY message from an untrusted source', file=sys.stderr)
    elif tp == b'RELAYED':
        handle_packet(idx+b'\0'+dat, True)
    else:
        print('Warning: dropping unknown message type:', tp, file=sys.stderr)

def handle_send_ack(idx, dat):
    snd0, dat = dat.split(b'\0', 1)
    if snd0 != self.encode('ascii'):
        send_pkt(os.urandom(8).hex().encode('ascii')+b'\0'+mb_encrypt(snd0, b'ACK\0'+snd0+b'\0'+idx))

def send_pkt(pkt):
    for i in peers: i.put(pkt)

sender_pool = {}
sender_queue = queue.Queue()

def sender_loop():
    while True:
        try:
            if sender_pool: sender_queue.get(timeout=0.25)
            else: sender_queue.get()
        except queue.Empty: pass
        for v in sender_pool.values(): send_pkt(os.urandom(8).hex().encode('ascii')+b'\0'+v)

def mb_encrypt(rec, msg):
    if rec in config['peers']:
        msg = b'EMSG\0'+cryptutil.encrypt(cryptutil.sign(self.encode('ascii')+b'\0'+msg, privkey), cryptutil.import_key(config['peers'][rec]), 'e')
    return msg

def send_msg(rec, dat):
    idx = os.urandom(8).hex().encode('ascii')
    msg = mb_encrypt(rec, b'MSG\0'+idx+b'\0'+rec.encode('ascii')+b'\0'+self.encode('ascii')+b'\0'+dat)
    return send_raw_msg(rec, idx, msg)

def send_raw_msg(rec, idx, msg):
    if rec in config['relays']:
        return send_msg(config['relays'][rec], b'RELAY\0'+rec.encode('ascii')+b'\0'+msg)
    sender_pool[idx] = msg
    sender_queue.put(None)
    return idx

def send_key_to(rec):
    idx = send_msg(rec, b'KEY\0'+pubkey.exportKey('DER'))

def input_loop():
    while True:
        cmd = input()
        if cmd.startswith('!'):
            cmd, args = cmd.split(' ', 1)
            if cmd == '!sendkey':
                idx = send_key_to(args)
                print('< [%s] sent key to %s'%(idx.decode('ascii', 'replace'), args))
            elif cmd == '!reqkey':
                idx = send_msg(args, b'NEEDKEY\0')
                print('< [%s] sent key request to %s'%(idx.decode('ascii', 'replace'), args))
            elif cmd == '!trust':
                config['trusted'].append(args)
                update_config()
                print('* now trusting', args)
            elif cmd == '!untrust':
                while True:
                    try: config['trusted'].remove(args)
                    except ValueError: break
                update_config()
                print('* not trusting', args, 'anymore')
            elif cmd == '!relay':
                who, overwho = args.split('|', 1)
                config['relays'][who] = overwho
                update_config()
                print('* relaying %s over %s'%(who, overwho))
            elif cmd == '!norelay':
                try: del config['relays'][args]
                except KeyError: pass
                print('* not relaying %s anymore'%args)
        else:
            rec, msg = cmd.split('|', 1)
            idx = send_msg(rec, b'MSG\0'+msg.encode('utf-8'))
            print('< [%s] sent to %s: %r'%(idx.decode('ascii', 'replace'), rec, msg))

def hpp(x):
    host, port = x.split(':')
    return (socket.gethostbyname(host), int(port))

def setup_peers():
    for i in sys.argv[2:]:
        a, b = i.split('-')
        q = queue.Queue()
        peer_main((hpp(a), hpp(b)), q)
        peers.append(q)

setup_peers()
threading.Thread(target=receiver_loop, daemon=True).start()
threading.Thread(target=sender_loop, daemon=True).start()
input_loop()
