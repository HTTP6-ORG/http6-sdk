import http.client, json, re, socket, sys

if len(sys.argv) != 4 or not re.fullmatch(r'[a-z0-9-]{1,48}', sys.argv[2]) or sys.argv[3] not in ('allowed', 'denied'):
    raise SystemExit('Usage: client.py SOCKET OP allowed|denied')
path, op, mode = sys.argv[1:]
proposal = {'op':op,'audience':'wallet','resource':'merchant-payment','args':{'network':'regtest','recipient':'merchant-a','satoshis':'100' if mode=='allowed' else '1100'},'holdSeconds':4}
raw = json.dumps(proposal, sort_keys=True, separators=(',', ':')).encode()
class LocalConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect(path)
c = LocalConnection('localhost', timeout=15)
try:
    c.request('POST','/http6/v0/propose',raw,{'Content-Type':'application/json','Connection':'close'})
    response=c.getresponse()
    print(json.dumps({'status':response.status,'body':json.loads(response.read())},separators=(',',':')))
finally:
    c.close()
