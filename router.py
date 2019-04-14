import random

class RouteSet:
    def __init__(self, sockets):
        self.sockets0 = sockets
        self.sockets = [(0, i) for i in sockets]
    def recalc(self, sock0=None):
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
    def send(self, pkt):
        self.recalc()
        max(self.sockets, key=lambda x:x[0])[1].put(pkt)
