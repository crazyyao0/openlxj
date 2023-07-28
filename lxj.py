import re
import socket
import random
from datetime import datetime 
from hashlib import md5

register_template = '''REGISTER sip:{server} SIP/2.0\r
Via: SIP/2.0/UDP {localip}:{localport};rport\r
Route: <sip:{server}:6000>\r
From: <sip:{username}@{server}>\r
To: <sip:{username}@{server}>\r
Contact: <sip:{username}@{localip}:{localport};ob>\r
Call-ID: {callid}\r
CSeq: {seq} REGISTER\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
'''
auth_template = '''REGISTER sip:{server} SIP/2.0\r
Via: SIP/2.0/UDP {localip}:{localport};rport\r
Route: <sip:{server}:6000>\r
From: <sip:{username}@{server}>\r
To: <sip:{username}@{server}>\r
Contact: <sip:{username}@{localip}:{localport};ob>\r
Call-ID: {callid}\r
CSeq: {seq} REGISTER\r
Max-Forwards: 70\r
Authorization: Digest {auth}\r
Content-Length: 0\r
\r
'''
unlock_template = '''MESSAGE sip:{lockaddr}@{server} SIP/2.0\r
Via: SIP/2.0/UDP {localip}:{localport};rport\r
Route: <sip:{server}:6000>\r
From: <sip:{username}@{server}>\r
To: <sip:{lockaddr}@{server}>\r
Contact: <sip:{username}@{localip}:{localport};ob>\r
Call-ID: {callid}\r
CSeq: {seq} MESSAGE\r
Max-Forwards: 70\r
Content-Type: application/xml\r
Content-Length: 174\r
\r
<MESSAGE Version='1.0'><HEADER MsgType='MSG_UNLOCK_REQ' MsgSeq='1'/><INFO LockNumber='{locknumber}' Scene='1' ClientType='1' OperateId='6a452cb0-695d-45e4-bcbc-0aaa751682f9'/></MESSAGE>'''

class lxjclient:
    def __init__(self, username, passwd):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", 0))
        self.ctx = {}
        self.ctx["localip"], self.ctx["localport"] = self.sock.getsockname()
        self.ctx["username"] = username
        self.ctx["passwd"] = passwd
        self.ctx["seq"] = random.randint(0,10000)
        self.ctx["callid"] = "".join(random.choices("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=36))
        self.ctx["server"] = "sip.hori-gz.com"
        self.ctx["cnonce"] = "".join(random.choices("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=36))

    def print_message(self, data):
        print("\n".join(data.splitlines()))

    def do_auth(self):
        HA1 = "{username}:{server}:{passwd}".format(**self.ctx)
        HA1 = md5(HA1.encode()).hexdigest()
        HA2 = "REGISTER:sip:sip.hori-gz.com"
        HA2 = md5(HA2.encode()).hexdigest()
        HA3 = "{HA1}:{nonce}:00000001:{cnonce}:auth:{HA2}".format(HA1=HA1, HA2=HA2, **self.ctx)
        HA3 = md5(HA3.encode()).hexdigest()
        return 'username={username}, realm="sip.hori-gz.com", uri="sip:sip.hori-gz.com", nonce="{nonce}", cnonce="{cnonce}", response="{HA3}", algorithm="MD5", qop="auth", nc=00000001'.format(HA3=HA3, **self.ctx)

    def send(self, template):
        self.ctx["seq"] += 1
        req = template.format(**self.ctx)
        #self.print_message(req)
        self.sock.sendto(req.encode(), (self.ctx["server"], 6000))
    
    def recv(self):
        data, _ = self.sock.recvfrom(10240)
        data = data.decode()
        #self.print_message(data)
        return data
    
    def unlockdoor(self, lockaddr, locknumber):
        self.ctx["lockaddr"] = lockaddr
        self.ctx["locknumber"] = locknumber
        
        print(datetime.now(), "Sending Registration...")
        self.send(register_template)
        data = self.recv()
        print(datetime.now(), "Received Challenge:", data.splitlines()[0][8:])
        
        self.ctx["localport"] = int(re.search("rport=(\d+);", data)[1])
        self.ctx["localip"] = re.search("received=([0-9.]+)", data)[1]
        if data.startswith("SIP/2.0 401"):
            self.ctx["nonce"] = re.search('nonce="([^"]+)"', data)[1]
            self.ctx["auth"] = self.do_auth()
            
            print(datetime.now(), "Sending Authorization...")
            self.send(auth_template)
            data = self.recv()
            print(datetime.now(), "Received Authorization result:", data.splitlines()[0][8:])
        
        if data.startswith("SIP/2.0 200"):
            print(datetime.now(), "Sending Unlock request...")
            self.send(unlock_template)
            for _ in range(2):
                data = self.recv()
                if data.startswith("SIP/2.0"):
                    print(datetime.now(), "Received Unlock confirmation:", data.splitlines()[0][8:])
                elif data.startswith("MESSAGE"):
                    result = re.search('RESULT Value="([^"]+)"', data)[1]
                    print(datetime.now(), "Received Unlock result:", result)

if __name__ == "__main__":
    # username and password are used when you sign in the app. username is usually your mobile phone number
    client = lxjclient("xxxxxxxxx", "xxxxxxxx")
    # lockaddr and locknumber can be found from packet capture in the SIP session.
    client.unlockdoor("xxxxxxxx", x)
