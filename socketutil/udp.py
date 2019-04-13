import socket

def hpp(x):
    host, port = x.split(':')
    return (socket.gethostbyname(host), int(port))

def TheSocket(params):
    bind_addr, peer_addr = map(hpp, params.split('-'))
    sock = socket.socket(socket.AF_INET6 if ':' in peer_addr[0] else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind_addr)
    sock.connect(peer_addr)
    return sock
