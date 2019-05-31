import sys, threading

def warn(msg):
    print(msg, file=sys.stderr)

def event(*args):
    if args[0] == 'i_am':
        print("I'm", args[1])
    elif args[0] == 'delivered':
        print('> [%s] delivered'%args[1])
    elif args[0] == 'msg_pkt_id':
        print('> [%s] message #%s'%(args[2], args[1]))
    elif args[0] == 'originally_written':
        print('> [%s] (originally written to %s)'%(args[1], args[2]))
    elif args[0] == 'incoming_msg':
        print('> [%s] %s wrote: %s'%(args[1], args[2], args[3]))
    elif args[0] == 'was_forwarded':
        print('> [%s] forwarded by %s'%(args[1], args[2]))
    elif args[0] == 'incoming_contact':
        print('> [%s] %s sent a contact'%(args[1], args[2]))
    elif args[0] == 'sent_key':
        print('< [%s] sent key to %s'%(args[1], args[2]))
    elif args[0] == 'sent_key_req':
        print('< [%s] sent key request to %s'%(args[1], args[2]))
    elif args[0] == 'forwarded':
        print('< [%s] forwarded to %s: %s'%(args[1], args[2], args[3]))
    elif args[0] == 'no_such_msg':
        print('* no such msg: %s'%args[1])
    elif args[0] == 'no_public_key':
        print('* no known public key for %s'%args[1])
    elif args[0] == 'sent_contact':
        print('< [%s] sent contact of %s to %s'%(args[1], args[3], args[2]))
    elif args[0] == 'sent_contact_file':
        print('< [%s] sent contact from %r to %s'%(args[1], args[3], args[2]))
    elif args[0] == 'no_contact':
        print('* no contact in %s'%args[1])
    elif args[0] == 'sent':
        print('< [%s] sent to %s: %r'%(args[1], args[2], args[3]))
    else:
        print('# event:', args)

def mainloop():
    while True:
        cmd = input()
        if cmd.startswith('!'):
            cmd, args = cmd.split(' ', 1)
            cmd = cmd[1:]
            if cmd in ('sendkey', 'reqkey', 'import', 'importfile', 'unimport', 'unimportfile', 'socket'):
                command(cmd, args)
            elif cmd in ('trust', 'untrust', 'norelay'):
                command(cmd, args)
                print({
                    'trust': '* now trusting %s',
                    'untrust': '* not trusting %s anymore',
                    'norelay': '* not relaying %s anymore'
                }[cmd]%args)
            elif cmd in ('forward', 'sendpeer', 'sendfile'):
                command(cmd, *args.split('|', 1))
            elif cmd == 'nickname':
                who, nick = args.split('@', 1)
                command(cmd, who, nick)
                print('* %s is now @%s'%(who, nick))
            elif cmd == 'relay':
                who, overwho = args.split('|', 1)
                command('relay', who, overwho)
                print('* relaying %s over %s'%(who, overwho))
        else:
            rec, msg = cmd.split('|', 1)
            command('sendmsg', rec, msg.encode('utf-8'))
