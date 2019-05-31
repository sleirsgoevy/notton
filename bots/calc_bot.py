BOT_KEY = 'MIICXAIBAAKBgQC4i3cL+G81cFuuXv4KX6CpfbTJ874HR26DrjRH4cOHoCqoGhoy7NNEi34yLHgozBQPbcZsH3vekf5fDxEUqqRY63OpPd4fqHmwRpA1uhAxmBTiB/u09Et85IcP26BmCQdTxOulg2bNjoe6wTFN6A5zYn1mYeGufpb0ArHbz9dGvQIDAQABAoGAFq2AwBZT6C+5/HgM5M5yilF5xXVv7SoQgRsHrqumIQUEKOsoPAjRP3Oa2uSPEYhekLTPNNs7mBK9vQW3diAwGM1Yjq61xM3md3CSnPRyzJ0u/4Qe24GDTsxQXZkghwJdMwgqDL8gEsEMkYclV2ehSfuBUbII+gyYgPIc1CyEY5sCQQC+mfn8EOr8PMZPyLWs8z1BueWs/qvJLxAGw8FgH/ow/yByG0JSalfHD96+1+Qc6Xwx7ASdSKZHvNbyeOQL3+8bAkEA9917d4ILP5iHxXmvB/SZK+pnfbxwk7al34WcJ7zgaWvLNUfpN6rRYvpYJextsDrtV5fgRUifhSSK3ovD1GoHBwJAQ+TzcH/SRNGdTrRPSvFGY9BFaS86oCqcidxXWNdrNuLaeusM3/CzndwgW1jqEAZ30AyjxCcp3Cn/Y1X+3eAB+wJAJCgS0qQNsAE4DP5rIeX0UgunfRf39BQ4rhp3ZPSQZ9BpnCQZSR2J3b5XDXEnrwVpidWFyZWGb42dFEmfD2VIEQJBAI20D5NTavrxODFfgXkiymBMXZkJRAtTBwCqIRhsegoQWesyIaepDBqdeWXFK9PIgxVZM9sEGsNYvPV+9vd3Hmo='

import cryptutil, queue, os

bot_key = cryptutil.import_key(BOT_KEY)
bot_hash = cryptutil.hash(bot_key.publickey())

known_keys = {}
known_pkts = set()
known_msgs = set()

class TheSocket:
    def __init__(self):
        self.queue = queue.Queue()
    def recv(self, x):
        return self.queue.get()
    def send_encrypted_back(self, sndr, x):
        sndr1 = sndr.decode('ascii', 'replace')
        self.queue.put(os.urandom(8).hex().encode('ascii')+b'\0eMSG\0'+sndr+b'\0'+cryptutil.encrypt(cryptutil.sign(bot_hash.encode('ascii')+b'\0'+x, bot_key), known_keys[sndr1], 'e'))
    def sendall(self, x):
        try:
            msgid, tp, dat0 = x.split(b'\0', 2)
            if msgid in known_pkts: return
            known_pkts.add(msgid)
            if tp == b'eMSG':
                tgt, dat = dat0.split(b'\0', 1)
                if tgt == bot_hash.encode('ascii'):
                    dat2 = cryptutil.decrypt(dat, bot_key, 'd')
                    sndr, tp2, dat3 = dat2.split(b'\0', 2)
                    if tp2 == b'MSG':
                        msgid2, rec, sndr2, tp3, dat4 = dat3.split(b'\0', 4)
                        if tp3 == b'KEY':
                            key = cryptutil.import_binary_key(dat4[:-128])
                            known_keys[cryptutil.hash(key)] = key
                    sndr1 = sndr.decode('ascii', 'replace')
                    if sndr1 in known_keys:
                        if not cryptutil.check_sign(dat2, known_keys[sndr1]): print('Badly signed!')
                        if tp2 == b'MSG':
                            if msgid2 in known_msgs: return
                            known_msgs.add(msgid2)
                            if tp3 == b'MSG':
                                try: ans = repr(eval(dat4[:-128].decode('utf-8'))).encode('utf-8')
                                except: ans = b'An error occurred.'
                                self.send_encrypted_back(sndr, b'MSG\0'+os.urandom(8).hex().encode('ascii')+b'\0'+sndr+b'\0'+bot_hash.encode('ascii')+b'\0MSG\0'+ans)
                            self.send_encrypted_back(sndr, b'ACK\0'+bot_hash.encode('ascii')+b'\0'+sndr+b'\0'+msgid2)
                    else: self.queue.put(os.urandom(8).hex().encode('ascii')+b'\0MSG\0'+os.urandom(8).hex().encode('ascii')+b'\0'+sndr+b'\0'+bot_hash.encode('ascii')+b'\0NEEDKEY\0')
        except Exception:
            import traceback
            traceback.print_exc()
