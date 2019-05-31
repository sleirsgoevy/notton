import threading, queue, os, socket, sys, json, cryptutil, socketutil, router, dbhelper
from collections import defaultdict
from frontend_helper import frontend

config = json.loads(open(sys.argv[1]+'/config.json').read())
privkey = cryptutil.import_key(config['privkey'])
pubkey = privkey.publickey()
msgq = queue.Queue()
peers = []
rs = router.RouteMap(peers, config['exclusive']) #defaultdict(lambda: router.RouteSet(peers))

def update_config():
    with open(sys.argv[1]+'/config.json', 'w') as file:
        print(json.dumps(config), file=file)

def peer_main(addr, q):
#   a1, a2 = addr
#   x = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#   x.bind(a1)
#   x.connect(a2)
    x = [socketutil.create_socket(addr)]
    q.addr = addr
    def sender_thread():
        while True:
            msg, rec = q.get()
            if rec != None and rec in config['exclusive'] and config['exclusive'][rec] != addr: continue
#           elif (rec == None or rec not in config['exclusive'] or config['exclusive'][rec] != addr) and addr.startswith('python://'): continue
            try: x[0].sendall(msg)
            except:
                try: x[0].close()
                except: pass
                x[0] = socketutil.create_socket(addr)
    def receiver_thread():
        while True:
            try: msgq.put((x[0].recv(1048576), q))
            except: pass
    threading.Thread(target=sender_thread, daemon=True).start()
    threading.Thread(target=receiver_thread, daemon=True).start()

pkt_cache = set()
self = cryptutil.hash(pubkey)
if self not in config['peers']:
    config['peers'][self] = cryptutil.export_key(pubkey)
    update_config()
frontend.event('i_am', self)

saved_msgs = dbhelper.DBDict('msgs', binary=True)
saved_contacts = dbhelper.DBDict('contacts', binary=True)

def receiver_loop():
    while True:
        msg, snd = msgq.get()
        try: handle_packet(msg, sender=snd)
        except:
            sys.excepthook(*sys.exc_info())
            frontend.warn('Note: caused by: %r'%msg)

F_RELAYED = 1
F_VERIFIED = 2
F_FORWARDED = 4
F_ENCRYPTED = 8
F_EMSG_NOFORWARD = 16

def handle_packet(msg, flags=0, verified_as=None, sender=None):
    if flags & F_FORWARDED: flags |= F_RELAYED
    idx, tp, dat = msg.split(b'\0', 2)
    if idx in pkt_cache: return
    pkt_cache.add(idx)
#   print('[relayed=%r][verified=%r][forwarded=%r] %r'%(bool(flags&F_RELAYED), bool(flags&F_VERIFIED), bool(flags&F_FORWARDED), msg))
    if tp == b'EMSG':
#       if not (flags & F_EMSG_NOFORWARD): print('true EMSG! hi anonymity!')
        dat0 = cryptutil.decrypt(dat, privkey, 'd')
        if flags & F_EMSG_NOFORWARD: flags &= ~F_EMSG_NOFORWARD
        else: send_pkt(msg)
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
            elif tp0 == b'ACK': return
            if snd not in config['peers']:
                send_msg(snd, b'NEEDKEY\0')
                return
        if not cryptutil.check_sign(dat0, cryptutil.import_key(config['peers'][snd])):
            frontend.warn('Warning: invalid EMSG signature')
            return
        else:
            pkt_cache.remove(idx)
            msgid = handle_packet(idx+b'\0'+dat, flags | F_VERIFIED | F_ENCRYPTED, snd, sender)
            if msgid != None:
                saved_msgs[msgid.decode('ascii', 'replace')] = b'SIGNED\0'+dat0
            return msgid
    if tp == b'eMSG':
        rec, dat0 = dat.split(b'\0', 1)
        if rec != self.encode('ascii'):
            send_pkt(msg, rec.decode('ascii', 'replace'))
            return
        else:
            pkt_cache.remove(idx)
            return handle_packet(idx+b'\0EMSG\0'+dat0, flags | F_EMSG_NOFORWARD, verified_as, sender)
    if tp == b'SIGNED':
        dat0 = dat
        snd, dat = dat0[:-128].split(b'\0', 1)
        snd = snd.decode('ascii', 'replace')
        if snd not in config['peers']:
            frontend.warn('Warning: could not validate SIGNED message, no public key available')
        elif not cryptutil.check_sign(dat0, cryptutil.import_key(config['peers'][snd])):
            frontend.warn('Warning: dropping incorrectly SIGNED message')
            return
        pkt_cache.remove(idx)
        return handle_packet(idx+b'\0'+dat, flags | F_VERIFIED, snd, sender)
    if tp == b'MSG' and not (flags & F_RELAYED):
        idx2, rec, dat0 = dat.split(b'\0', 2)
        if rec == self.encode('ascii'):
            handle_send_ack(idx2, dat0)
    if tp == b'MSG':
        idx2, rec, dat = dat.split(b'\0', 2)
        if rec == self.encode('ascii') or (flags & F_FORWARDED):
            handle_incoming(idx, idx2, dat, flags, verified_as, rec)
            saved_msgs[idx2.decode('ascii', 'replace')] = msg.split(b'\0', 1)[1]
            return idx2
        else:
            send_pkt(msg, rec)
    elif tp == b'ACK':
        snd, rec, idx2 = dat.split(b'\0', 2)
        if rec == self.encode('ascii'): 
            try: del sender_pool[idx2.decode('ascii', 'replace')]
            except KeyError: pass
            else: rs[snd].recalc(sender)
            frontend.event('delivered', idx2.decode('ascii', 'replace'))
        else:
            send_pkt(msg, rec)
    else:
        frontend.warn('Warning: dropping unrecognized packet: %r'%msg)

msg_cache = set()

def handle_incoming(pktid, idx, dat, flags, verified_as, rec):
    if not (flags & F_FORWARDED):
        if idx in msg_cache: return
        msg_cache.add(idx)
    frontend.event('msg_pkt_id', idx.decode('ascii', 'replace'), pktid.decode('ascii', 'replace'))
#   print(dat)
    snd0, tp, dat = dat.split(b'\0', 2)
    snd = snd0.decode('ascii', 'replace')
    if not (flags & F_VERIFIED) and snd in config['peers']:
        frontend.warn('Warning: message %s not verified, may be spoofed'%idx.decode('ascii', 'replace'))
    elif (flags & F_VERIFIED) and snd != verified_as:
        frontend.warn('Warning: message %s: sender spoofed, dropping'%idx.decode('ascii', 'replace'))
        return
    if rec != self.encode('ascii'):
        frontend.event('originally_written', idx.decode('ascii', 'replace'), format_nickname(rec.decode('ascii', 'replace')))
#   print('message:', snd0, tp, dat)
    if tp == b'NEEDKEY':
        send_key_to(snd)
        return
    if tp == b'MSG':
        frontend.event('incoming_msg', idx.decode('ascii', 'replace'), format_nickname(snd), dat)
    elif tp == b'KEY':
        key = cryptutil.import_binary_key(dat)
        config['peers'][cryptutil.hash(key)] = cryptutil.export_key(key)
    elif tp == b'RELAY':
        tgt, relayed, msg = dat.split(b'\0', 2)
        tgt = tgt.decode('ascii', 'replace')
        if snd in config['trusted'] and not (flags & F_FORWARDED) or tgt in config['exclusive'] and config['exclusive'][tgt].startswith('python://'):
            send_msg(tgt, b'RELAYED\0'+msg, relay_idx = float('inf') if relayed == b'0' else 0)
        else:
            frontend.warn('Warning: RELAY message from an untrusted source')
    elif tp == b'RELAYED':
        handle_packet(idx+b'\0'+dat, F_RELAYED)
    elif tp == b'FORWARD':
        frontend.event('was_forwarded', idx.decode('ascii', 'replace'), format_nickname(snd0.decode('ascii', 'replace')))
        handle_packet(idx+b'\0'+dat, F_FORWARDED)
    elif tp == b'CONTACT':
        saved_contacts[idx.decode('ascii', 'replace')] = dat
        frontend.event('incoming_contact', idx.decode('ascii', 'replace'), format_nickname(snd0.decode('ascii', 'replace')))
    else:
        frontend.warn('Warning: dropping unknown message type: %r'%tp)

def handle_send_ack(idx, dat):
    snd0, dat = dat.split(b'\0', 1)
    send_pkt(os.urandom(8).hex().encode('ascii')+b'\0'+mb_encrypt(snd0.decode('ascii', 'replace'), None, b'ACK\0'+self.encode('ascii')+b'\0'+snd0+b'\0'+idx), snd0.decode('ascii', 'replace'))

def send_pkt(pkt, rec=None):
    if rec != None:
        rs[rec].send(pkt, rec)
    else:
        for i in peers: i.put((pkt, rec))

sender_pool = dbhelper.DBDict('sender_pool')
sender_queue = queue.Queue()

def sender_loop():
    while True:
        try:
            if sender_pool: sender_queue.get(timeout=0.25)
            else: sender_queue.get()
        except queue.Empty: pass
        for k, v in list(sender_pool.values()): send_pkt(os.urandom(8).hex().encode('ascii')+b'\0'+v, k)

def mb_encrypt(rec, idx, msg):
    if idx != None:
        saved_msgs[idx.decode('ascii', 'replace')] = msg
    if rec in config['peers']:
        signed = cryptutil.sign(self.encode('ascii')+b'\0'+msg, privkey)
        if idx != None:
            saved_msgs[idx.decode('ascii', 'replace')] = b'SIGNED\0'+signed
        msg = b'eMSG\0'+rec.encode('ascii')+b'\0'+cryptutil.encrypt(signed, cryptutil.import_key(config['peers'][rec]), 'e')
    return msg

def send_msg(rec, dat, rec0=None, relay_idx=0):
#   print(rec, dat)
    idx = os.urandom(8).hex().encode('ascii')
    msg = mb_encrypt(rec, idx, b'MSG\0'+idx+b'\0'+rec.encode('ascii')+b'\0'+self.encode('ascii')+b'\0'+dat)
    return send_raw_msg(rec, idx, msg, rec0, relay_idx)

def send_raw_msg(rec, idx, msg, rec0=None, relay_idx=0):
    if rec0 == None:
        rec0 = rec
    if rec0 in config['relays'] and relay_idx <= config['relays'][rec0].count('|'):
        return send_msg(config['relays'][rec0].split('|')[relay_idx], b'RELAY\0'+rec.encode('ascii')+b'\x001\0'+msg, rec0, relay_idx + 1)
    sender_pool[idx.decode('ascii', 'replace')] = (rec, msg)
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
                print('*', format_nickname(cryptutil.hash(cryptutil.import_key(k))))
                if v != None:
                    print('      (@%s)'%v)
                if k in c['trusted']:
                    print('      (trusted)')
            print('Sockets:')
            for x in c['sockets']:
                print('*', x)
            print('Relays:')
            for k, v in c['relays'].items():
                print('* %s via %s'%(format_nickname(k), format_nickname(v)))
            print('Exclusive routes:')
            for k, v in c['exclusive'].items():
                print('* %s excl. via %s'%(format_nickname(k), v))
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
        config['exclusive'].update(c['exclusive'])
        update_config()
    except:
        print('Error during contact import:', file=sys.stderr)
        sys.excepthook(*sys.exc_info())

def unimport_contact(c, interactive=True):
    try:
        if isinstance(c, bytes):
            c = json.loads(c.decode('utf-8'))
        if interactive:
            print('Unimport this contact?')
            print('Peers:')
            for k, v in c['peers'].items():
                print('*', format_nickname(cryptutil.hash(cryptutil.import_key(k))))
                if v != None:
                    print('      (@%s)'%v)
                if k in c['trusted']:
                    print('      (trusted)')
            print('Sockets:')
            for x in c['sockets']:
                print('*', x)
            print('Relays:')
            for k, v in c['relays'].items():
                print('* %s via %s'%(format_nickname(k), format_nickname(v)))
            print('Exclusive routes:')
            for k, v in c['exclusive'].items():
                print('* %s excl. via %s'%(format_nickname(k), v))
            try: input('Press Enter to continue, Ctrl+C to abort')
            except KeyboardInterrupt: return
        for k, v in c['peers'].items():
            try: del config['peers'][cryptutil.hash(cryptutil.import_key(k))]
            except KeyError: frontend.warn('Warning: %s was not in your contacts'%cryptutil.hash(cryptutil.import_key(k)))
            if v != None:
                try: del config['nicknames'][cryptutil.hash(cryptutil.import_key(k))]
                except KeyError: frontend.warn('Warning: @%s was not in your contacts'%v)
            if cryptutil.hash(cryptutil.import_key(k)) in c['trusted']:
                try: config['trusted'].remove(cryptutil.hash(cryptutil.import_key(k)))
                except ValueError: frontend.warn('Warning: %s was not in your trust list'%cryptutil.hash(cryptutil.import_key(k)))
        for x in c['sockets']:
            if x in config['sockets']:
#               start_peer_socket(x)
                try: config['sockets'].remove(x)
                except ValueError: frontend.warn('Warning: socket %s was not in your socket list'%x)
                else: frontend.warn('Note: socket %s removed from your socket list, will be disconnected on client restart'%x)
        for r in c['relays']:
            try: del config['relays'][r]
            except ValueError: frontend.warn('Warning: no relay was configured for %s'%r)
        for r in c['exclusive']:
            try: del config['exclusive'][r]
            except ValueError: frontend.warn('Warning: no exclusive socket was configured for %s'%r)
        update_config()
    except:
        print('Error during contact unimport:', file=sys.stderr)
        sys.excepthook(*sys.exc_info())

def command(*cmd):
    cmd, *args = cmd
    if cmd == 'sendkey':
        idx = send_key_to(parse_nickname(args[0]))
        frontend.event('sent_key', idx.decode('ascii', 'replace'), args)
    elif cmd == 'reqkey':
        idx = send_msg(parse_nickname(args[0]), b'NEEDKEY\0')
        frontend.event('sent_key_req', idx.decode('ascii', 'replace'), args[0])
    elif cmd == 'trust':
        config['trusted'].append(parse_nickname(args[0]))
        update_config()
    elif cmd == 'untrust':
        while True:
            try: config['trusted'].remove(parse_nickname(args[0]))
            except ValueError: break
        update_config()
    elif cmd == 'relay':
        who, overwho = args
        config['relays'][parse_nickname(who)] = parse_nickname(overwho)
        update_config()
    elif cmd == 'norelay':
        try: del config['relays'][parse_nickname(args[0])]
        except KeyError: pass
    elif cmd == 'forward':
        rec, msg = args
        msg = msg
#       print(repr(rec))
        if msg in saved_msgs:
            idx = send_msg(parse_nickname(rec), b'FORWARD\0'+saved_msgs[msg])
            frontend.event('forwarded', idx.decode('ascii', 'replace'), rec, msg)
        else:
            frontend.event('no_such_msg', msg)
    elif cmd == 'sendpeer':
        rec, who = args
        who = parse_nickname(who)
        if who not in config['peers']:
            frontend.event('no_public_key', who)
        else:
            nickname = config['nicknames'].get(who, None)
            idx = send_msg(parse_nickname(rec), b'CONTACT\0'+json.dumps({"peers": {config['peers'][who]: nickname}, "sockets": [], "relays": {}, "trusted": [], "exclusive": {}}).encode('utf-8'))
            frontend.event('sent_contact', idx.decode('ascii', 'replace'), rec, who)
    elif cmd == 'sendfile':
        rec, f = args
        try: data = open(f, 'rb').read()
        except IOError: frontend.warn('* cannot open file')
        else:
            idx = send_msg(parse_nickname(rec), b'CONTACT\0'+data)
            frontend.event('sent_contact_file', idx.decode('ascii', 'replace'), rec, f)
    elif cmd == 'import':
        if args[0] in saved_contacts:
            import_contact(saved_contacts[args[0]])
        else:
            frontend.event('no_contact', args[0])
    elif cmd == 'importfile':
        try: data = open(args[0], 'rb').read()
        except IOError: frontend.warn('* cannot open file')
        else: import_contact(data)
    elif cmd == 'unimport':
        if args[0] in saved_contacts:
            unimport_contact(saved_contacts[args[0]])
        else:
            frontend.event('no_contact', args[0])
    elif cmd == 'unimportfile':
        try: data = open(args[0], 'rb').read()
        except IOError: frontend.warn('* cannot open file')
        else: unimport_contact(data)
    elif cmd == 'socket':
        start_peer_socket(args)
        config['sockets'].append(args)
        update_config()
    elif cmd == 'nickname':
        who, nick = args
        config['nicknames'][who] = nick
        update_config()
    elif cmd == 'sendmsg':
        rec, msg = args
        idx = send_msg(parse_nickname(rec), b'MSG\0'+msg)
        frontend.event('sent', idx.decode('ascii', 'replace'), rec, msg)

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
frontend.command = command
frontend.config = config
frontend.mainloop()
