BOT_KEY = 'MIICXAIBAAKBgQDDSRdeGz7KsA+KYbP9e/T741RWphm8gEH1CAulYQULItkrHPy51kufXdmK+j7ToTzOCUOHhBcSBqOgLsH/bpL9K7HY9WIlUjn0D522Sl1Jn6uSTrO3nWGBioPqRFPlxERZIKEj5A+tLS2Rlge9hLHUes3SRpx0vVb/VpEJlKGwAQIDAQABAoGAE6WrYa7pCthav+fjhWmutJbi+dK9PR9EQ4Q7M7jGmp+3bKR+cq3yLsbw55AUuRL8PJhnAF/UOF6NoMSDhRDZXc034++ZfFrNbCitZuDIl4/f0Ue7jpDec00ob8V/qsWDeBuy7/QL/Xdk3gwahx/SpUp5ma1rcj7SQEDKrGJrwAkCQQDU+cWP0ZCP3Y8xdSVYieEBA2mgpyaYH46KSqf1wdQUIWV0UyAnj1L0lq0Mv6PV7EzU8ZOPwwPRRI+p8nHM1T79AkEA6rx1BoCHPI4rrE2pkpYlpWDjN897PfFvyKd9NWnkmpkdScMlpsy+BzCMopLtxrKKG9F79jB7m72tCY17r6S+VQJAMFKz5tvv5xSoZtpjrOEr8mTp1I/Yi++tEee6kGJ4UlD5ihlKVG+KrQB7J0dcTy+chzyA9L+U4CikSDVAaO+BqQJBALm6LyXb4CTroGaOdFNFdbfqdx2bjrmuJHIxA4KVrIkeCOxp+YqGiPyLT1r6wiPq9BeaomhiaAsMArOCPJD22pkCQAWB6kQFWXRWwztpFeKR2i6gal7xKT9iFwuho5dKL+7pNOJb46hxG6zcf3hzgUgK/goU7Gn7f8nz75MxTPgWSEk='

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
                            if tp3 == b'RELAY':
                                msg2 = dat4[:-128].split(b'\0', 2)[2]
                                if msg2.startswith(b'eMSG\0'):
                                    msg2 = b'EMSG\0'+msg2.split(b'\0', 2)[2]
                                msg2 = msgid2+b'\0'+msg2
                                self.queue.put(msg2)
                            self.send_encrypted_back(sndr, b'ACK\0'+bot_hash.encode('ascii')+b'\0'+sndr+b'\0'+msgid2)
                    else: self.queue.put(os.urandom(8).hex().encode('ascii')+b'\0MSG\0'+os.urandom(8).hex().encode('ascii')+b'\0'+sndr+b'\0'+bot_hash.encode('ascii')+b'\0NEEDKEY\0')
        except Exception:
            import traceback
            traceback.print_exc()
