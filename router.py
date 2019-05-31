import random

class RouteSet:
    def __init__(self, sockets, exclusive, peer):
        self.sockets0 = sockets
        self.sockets = [(0, i) for i in sockets]
        self.exclusive = exclusive
        self.peer = peer
    def recalc(self, sock0=None):
        if self.peer in self.exclusive:
            trusted_sock = [i for i in self.sockets0 if i.addr == self.exclusive[self.peer]]
            assert len(trusted_sock) == 1
            sock0, = trusted_sock
        sockets2 = []
        sockets3 = []
        for i, j in self.sockets:
            if j not in self.sockets0: continue
            sockets3.append(j)
            if j is sock0:
                score = 100
            else:
                score = 0.9 * i + random.random()
            sockets2.append((score, j))
        for i in self.sockets0:
            if i not in sockets3: sockets2.append((0, i))
        self.sockets = sockets2
    def send(self, pkt, rec):
        self.recalc()
        max(self.sockets, key=lambda x:x[0])[1].put((pkt, rec))

class RouteMap(dict):
    def __init__(self, sockets, exclusive):
        dict.__init__(self)
        self.sockets = sockets
        self.exclusive = exclusive
    def __missing__(self, key):
        return RouteSet(self.sockets, self.exclusive, key)
