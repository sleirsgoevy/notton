import threading, queue, os, socket, sys, json, cryptutil, socketutil

config = json.loads(open(sys.argv[1]).read())
privkey = cryptutil.import_key(config['privkey'])
pubkey = privkey.publickey()
msgq = queue.Queue()
peers = []

def update_config():
    with open(sys.argv[1], 'w') as file:
        print(json.dumps(config), file=file)

def peer_main(addr, q):
#   a1, a2 = addr
#   x = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#   x.bind(a1)
#   x.connect(a2)
    x = socketutil.create_socket(addr)
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
if self not in config['peers']:
    config['peers'][self] = cryptutil.export_key(pubkey)
print('I\'m', self)

saved_msgs = {}
saved_contacts = {}

def receiver_loop():
    while True:
        msg = msgq.get()
        try: handle_packet(msg)
        except:
            sys.excepthook(*sys.exc_info())
            print('Note: caused by:', msg, file=sys.stderr)
        

def handle_packet(msg, is_relayed=False, is_verified=False, is_forwarded=False):
    if is_forwarded: is_relayed = True
    idx, tp, dat = msg.split(b'\0', 2)
    if idx in msg_cache: return
    msg_cache.add(idx)
#   print('[relayed=%r][verified=%r][forwarded=%r] %r'%(is_relayed, is_verified, is_forwarded, msg))
    if tp == b'EMSG':
        dat0 = cryptutil.decrypt(dat, privkey, 'd')
        send_pkt(msg)
        if dat0 == None:
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
            msgid = handle_packet(idx+b'\0'+dat, is_relayed, snd, is_forwarded)
            saved_msgs[msgid] = b'SIGNED\0'+dat0
            return msgid
    if tp == b'eMSG':
        rec, dat0 = dat.split(b'\0', 1)
        if rec != self.encode('ascii'):
            send_pkt(msg)
            return
        else:
            msg_cache.remove(idx)
            return handle_packet(idx+b'\0EMSG\0'+dat0, is_relayed, is_verified, is_forwarded)
    if tp == b'SIGNED':
        dat0 = dat
        snd, dat = dat0[:-128].split(b'\0', 1)
        snd = snd.decode('ascii', 'replace')
        if snd not in config['peers']:
            print('Warning: could not validate SIGNED message, no public key available', file=sys.stderr)
        elif not cryptutil.check_sign(dat0, cryptutil.import_key(config['peers'][snd])):
            print('Warning: dropping incorrectly SIGNED message', file=sys.stderr)
            return
        msg_cache.remove(idx)
        return handle_packet(idx+b'\0'+dat, is_relayed, snd, is_forwarded)
    if tp == b'MSG' and not is_relayed:
        idx2, rec, dat0 = dat.split(b'\0', 2)
        if rec == self.encode('ascii'):
            handle_send_ack(idx2, dat0)
    if tp == b'MSG':
        idx2, rec, dat = dat.split(b'\0', 2)
        if rec == self.encode('ascii') or is_forwarded:
            handle_incoming(idx2, dat, is_relayed, is_verified, rec)
            saved_msgs[idx2] = msg.split(b'\0', 1)[1]
            return idx2
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

def handle_incoming(idx, dat, is_relayed, is_verified, rec):
#   print(dat)
    if rec != self.encode('ascii'):
        print('> [%s] (originally written to %s)'%(idx.decode('ascii', 'replace'), format_nickname(rec.decode('ascii', 'replace'))))
    if not is_verified:
        print('Warning: message %s not verified, may be spoofed'%idx.decode('ascii', 'replace'), file=sys.stderr)
    snd0, tp, dat = dat.split(b'\0', 2)
    snd = snd0.decode('ascii', 'replace')
    if is_verified and snd != is_verified:
        print('Warning: message %s: sender spoofed, dropping', file=sys.stderr)
        return
    if tp == b'NEEDKEY':
        send_key_to(snd)
        return
    if tp == b'MSG':
        print('> [%s] %s wrote: %s'%(idx.decode('ascii', 'replace'), format_nickname(snd), dat))
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
    elif tp == b'FORWARD':
        print('> [%s] forwarded by %s'%(idx.decode('ascii', 'replace'), format_nickname(snd0.decode('ascii', 'replace'))))
        handle_packet(idx+b'\0'+dat, is_forwarded=True)
    elif tp == b'CONTACT':
        saved_contacts[idx.decode('ascii', 'replace')] = dat
        print('> [%s] %s sent a contact'%(idx.decode('ascii', 'replace'), format_nickname(snd0.decode('ascii', 'replace'))))
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
    return send_msg(rec, b'KEY\0'+pubkey.exportKey('DER'))

def import_contact(c, interactive=True):
    try:
        if isinstance(c, bytes):
            c = json.loads(c.decode('utf-8'))
        if interactive:
            print('Import this contact?')
            print('Peers:')
            for k, v in c['peers'].items():
                print('*', cryptutil.hash(cryptutil.import_key(k)))
                if v != None:
                    print('      (@%s)'%v)
                if k in c['trusted']:
                    print('      (trusted)')
            print('Sockets:')
            for x in c['sockets']:
                print('*', x)
            print('Relays:')
            for k, v in c['relays'].items():
                print('* %s via %s'%(k, v))
            try: input('Press Enter to continue, Ctrl+C to abort')
            except KeyboardInterrupt: return
        for k, v in c['peers'].items():
            config['peers'][cryptutil.hash(cryptutil.import_key(k))] = k
            if v != None:
                config['nicknames'][cryptutil.hash(cryptutil.import_key(k))] = v
            if cryptutil.hash(cryptutil.import_key(k)) in c['trusted']:
                config['trusted'].append(cryptutil.hash(cryptutil.import_key(k)))
        for x in c['sockets']:
            if x not in config['sockets']:
                start_peer_socket(x)
                config['sockets'].append(x)
        config['relays'].update(c['relays'])
        update_config()
    except:
        print('Error during contact import:', file=sys.stderr)
        sys.excepthook(*sys.exc_info())

def input_loop():
    while True:
        cmd = input()
        if cmd.startswith('!'):
            cmd, args = cmd.split(' ', 1)
            if cmd == '!sendkey':
                idx = send_key_to(parse_nickname(args))
                print('< [%s] sent key to %s'%(idx.decode('ascii', 'replace'), args))
            elif cmd == '!reqkey':
                idx = send_msg(parse_nickname(args), b'NEEDKEY\0')
                print('< [%s] sent key request to %s'%(idx.decode('ascii', 'replace'), args))
            elif cmd == '!trust':
                config['trusted'].append(parse_nickname(args))
                update_config()
                print('* now trusting', args)
            elif cmd == '!untrust':
                while True:
                    try: config['trusted'].remove(parse_nickname(args))
                    except ValueError: break
                update_config()
                print('* not trusting', args, 'anymore')
            elif cmd == '!relay':
                who, overwho = args.split('|', 1)
                config['relays'][parse_nickname(who)] = parse_nickname(overwho)
                update_config()
                print('* relaying %s over %s'%(who, overwho))
            elif cmd == '!norelay':
                try: del config['relays'][parse_nickname(args)]
                except KeyError: pass
                print('* not relaying %s anymore'%args)
            elif cmd == '!forward':
                rec, msg = args.split('|', 1)
                msg = msg.encode('ascii')
                if msg in saved_msgs:
                    idx = send_msg(parse_nickname(rec), b'FORWARD\0'+saved_msgs[msg])
                    print('< [%s] forwarded to %s: %s'%(idx.decode('ascii', 'replace'), rec, msg))
                else:
                    print('* no such msg: %s'%msg)
            elif cmd == '!sendpeer':
                rec, who = args.split('|', 1)
                who = parse_nickname(who)
                if who not in config['peers']:
                    print('* no known public key for', who)
                nickname = config['nicknames'].get(who, None)
                send_msg(parse_nickname(rec), b'CONTACT\0'+json.dumps({"peers": {config['peers'][who]: nickname}, "sockets": [], "relays": {}, "trusted": []}).encode('utf-8'))
            elif cmd == '!sendfile':
                rec, f = args.split('|', 1)
                try: data = open(f, 'rb').read()
                except IOError: print('* cannot open file')
                else: send_msg(parse_nickname(rec), b'CONTACT\0'+data)
            elif cmd == '!import':
                if args in saved_contacts:
                    import_contact(saved_contacts[args])
                else:
                    print('* no such contact')
            elif cmd == '!importfile':
                try: data = open(args, 'rb').read()
                except IOError: print('* cannot open file')
                else: import_contact(data)
            elif cmd == '!socket':
                start_peer_socket(args)
                config['sockets'].append(args)
                update_config()
                print('* socket opened')
            elif cmd == '!nickname':
                who, nick = args.split('@', 1)
                config['nicknames'][who] = nick
                update_config()
                print('* %s is now @%s'%(who, nick))
        else:
            rec, msg = cmd.split('|', 1)
            idx = send_msg(parse_nickname(rec), b'MSG\0'+msg.encode('utf-8'))
            print('< [%s] sent to %s: %r'%(idx.decode('ascii', 'replace'), rec, msg))

def start_peer_socket(addr):
    q = queue.Queue()
    peer_main(addr, q)
    peers.append(q)

def setup_peers():
    for i in config['sockets']:
#       a, b = i.split('-')
        start_peer_socket(i)

def parse_nickname(s):
    if s[:1] == '@' and s[1:] in config['nicknames'].values():
        return [i for i, j in config['nicknames'].items() if j == s[1:]][0]
    return s

def format_nickname(s):
    if s in config['nicknames']:
        s += '@' + config['nicknames'][s]
    return s

setup_peers()
threading.Thread(target=receiver_loop, daemon=True).start()
threading.Thread(target=sender_loop, daemon=True).start()
input_loop()
