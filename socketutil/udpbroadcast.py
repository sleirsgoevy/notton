import socket, os, fcntl
from .udp import hpp

class TheSocket:
    def __init__(self, params):
        self.iface = None
        if '/' in params:
            params, self.iface = params.split('/', 1)
        self.host, self.port = hpp(params)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
    def _send_to(self, iface, msg):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: addr = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8919, iface.encode('ascii')+bytes(256-len(iface)))[20:24])
        except OSError: pass
        else: self.sock.sendto(msg, (addr, self.port))
    def sendall(self, msg):
        if self.iface == None:
            for i in os.listdir('/sys/class/net'): self._send_to(i, msg)
        else:
            self._send_to(self.iface, msg)
    def recv(self, x):
        return self.sock.recv(x)
