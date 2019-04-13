import socket

def create_socket(addr):
    proto, params = addr.split('://', 1)
    if not proto.isalnum():
        raise socket.error("Unknown protocol")
    try: mod = getattr(__import__('socketutil.'+proto), proto)
    except ImportError:
        raise socket.error("Unknown protocol")
    return mod.TheSocket(params)
