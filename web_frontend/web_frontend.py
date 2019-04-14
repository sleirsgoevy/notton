import http.server, socketserver, os, sys, queue, json

logfile = open(sys.argv[1]+'/web_frontend.log', 'a+')
logfile.seek(0)
log_history = [json.loads(i) for i in logfile.readlines()]

event_queue = queue.Queue()

def json_bytes(x):
    if isinstance(x, bytes): return x.decode('latin-1')
    raise TypeError

def event(*args):
    print(json.dumps(args, default=json_bytes), file=logfile)
    logfile.flush()
    event_queue.put(args)

def warn(msg):
    event('warn', msg)

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        return http.server.SimpleHTTPRequestHandler.translate_path(self, path).replace(os.getcwd(), 'web_frontend')
    def do_POST(self):
        if self.path == '/loghistory':
            ans = json.dumps(log_history, default=json_bytes)
        elif self.path == '/config':
            ans = json.dumps(config)
        else:
            l = int(self.headers.get('Content-Length', '0'))
            data = b''
            while len(data) < l: data += self.rfile.read(l - len(data))
            if not data:
                try: ans = json.dumps(event_queue.get(timeout=3), default=json_bytes)
                except queue.Empty: ans = 'null'
                else: log_history.append(json.loads(ans))
            else:
                cmd = json.loads(data.decode('utf-8'))
                if cmd[0] == 'sendmsg':
                    cmd[2] = cmd[2].encode('latin-1')
                command(*cmd)
                ans = 'null'
        ans = ans.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(ans))
        self.end_headers() 
        self.wfile.write(ans)

class RequestServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def mainloop():
    RequestServer(('127.0.0.1', int(sys.argv[3])), RequestHandler).serve_forever()
