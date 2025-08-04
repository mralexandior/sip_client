import socket
import re
import hashlib
import random
import time


sip_cfg = {
    'sip_server_addr': '10.120.0.127',
    'sip_server_port': 5060,
    'local_ip': '10.120.0.115',
    'local_port': 5066,
    'username': '1000',
    'password': '1000',
    'to_user': '1002',
    'call_id': '1000@10.120.0.115',
    'tag': f'{random.randint(1000, 9999)}',
    'branch': f'z9hG4bK-{random.randint(100000, 999999)}',
    'cseq': 1,
    'contact': '',
    'uri_register': '',
    'uri_invite': ''
}
sip_cfg['contact'] = f'sip:{sip_cfg["username"]}@{sip_cfg["local_ip"]}:{sip_cfg["local_port"]}'
sip_cfg['uri_register'] = f'sip:{sip_cfg["sip_server_addr"]}:{sip_cfg["sip_server_port"]}'
sip_cfg['uri_invite'] = f'sip:{sip_cfg['to_user']}@{sip_cfg["sip_server_addr"]}'


def create_sdp():
    res = []
    res.append('v=0')
    res.append(f'o={sip_cfg["username"]} 0 0 IN IP4 {sip_cfg["local_ip"]}')
    res.append('s=-')
    res.append(f'c=IN IP4 {sip_cfg['local_ip']}')
    res.append('t=0 0')
    res.append('m=audio 8000 RTP/AVP 0')
    res.append('a=rtpmap:0 PCMU/8000')
    return '\r\n'.join(res)


def calculate_response(username, password, realm, method, uri, nonce):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def extract_auth_params(response):
    auth_line = re.search(r'WWW-Authenticate: Digest (.+)', response)
    if not auth_line:
        return None
    return dict(re.findall(r'(\w+)="([^"]+)"', auth_line.group(1)))


def create_register_header(nonce=None, realm=None):
    res = []
    response = ''

    res.append(f'REGISTER sip:{sip_cfg["sip_server_addr"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {sip_cfg["local_ip"]}:{sip_cfg["local_port"]};branch={sip_cfg["branch"]}-reg')
    res.append('Max-Forwards: 70')
    res.append(f'Contact: <{sip_cfg["contact"]}>')
    res.append(f'To: <sip:{sip_cfg["username"]}@{sip_cfg["sip_server_addr"]}>')
    res.append(f'From: <sip:{sip_cfg["username"]}@{sip_cfg["sip_server_addr"]}>;tag={sip_cfg["tag"]}')
    res.append(f'Call-ID: {call_id}')
    res.append(f'CSeq: {sip_cfg["cseq"]} REGISTER')
    res.append('Expires: 300')
    # res.append('Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, INFO, MESSAGE')
    # res.append('Supported: replaces')
    res.append('User-Agent: PythonScript')

    if nonce and realm:
        print("using auth..")
        response = calculate_response(sip_cfg['username'], sip_cfg['password'], realm, 
                                      'REGISTER', sip_cfg['uri_register'], nonce)
        
        cnonce = hashlib.md5(f"{sip_cfg['username']}:{realm}:{sip_cfg['password']}".encode()).hexdigest()
        nc = str(sip_cfg['cseq']).zfill(8)
        auth_header = f'Authorization: Digest username="{sip_cfg["username"]}"'
        auth_header += f',realm="{realm}"'
        auth_header += f',nonce="{nonce}"'
        auth_header += f',uri="{sip_cfg["uri_register"]}"'
        auth_header += f',response="{response}"'
        # auth_header += f',cnonce="{cnonce}"'
        # auth_header += f',nc={nc}'
        # auth_header += ',qop=auth'
        # auth_header += f',opaque="{opaque}"'
        auth_header += f',algorithm=MD5'

        res.append(auth_header)
        res.append('Content-Length: 0\r\n')

    return '\r\n'.join(res)
    

def create_invite_header(nonce=None, realm=None):
    res = []
    response = ''

    res.append(f'INVITE {sip_cfg["uri_invite"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {sip_cfg["local_ip"]}:{sip_cfg["local_port"]};branch={sip_cfg["branch"]}')
    res.append('Max-Forwards: 70')
    res.append(f'To: <{sip_cfg["uri_invite"]}>')
    res.append(f'From: <sip:{sip_cfg["username"]}@{sip_cfg["sip_server_addr"]}>;tag={sip_cfg["tag"]}')
    res.append(f'Call-ID: {call_id}@{sip_cfg["sip_server_addr"]}')
    res.append(f'CSeq: {sip_cfg["cseq"]} INVITE')
    res.append(f'Contact: <{sip_cfg["contact"]}>')
    res.append('Content-Type: application/sdp')

    if nonce and realm:
        print("using auth..")
        response = calculate_response(sip_cfg['username'], sip_cfg['password'], realm,
                                       'INVITE', sip_cfg['uri_invite'], nonce)
        
        cnonce = hashlib.md5(f"{sip_cfg['username']}:{realm}:{sip_cfg['password']}".encode()).hexdigest()
        nc = str(sip_cfg['cseq']).zfill(8)
        auth_header = f'Authorization: Digest username="{sip_cfg["username"]}"'
        auth_header += f',realm="{realm}"'
        auth_header += f',nonce="{nonce}"'
        auth_header += f',uri="{sip_cfg["uri_invite"]}"'
        auth_header += f',response="{response}"'
        # auth_header += f',cnonce="{cnonce}"'
        # auth_header += f',nc={nc}'
        # auth_header += ',qop=auth'
        # auth_header += f',opaque="{opaque}"'
        auth_header += f',algorithm=MD5'

        res.append(auth_header)
        res.append(f'Content-Length: {len(sdp)}\r\n')
        res.append(sdp)

    return '\r\n'.join(res)
    

def create_bye_header():
    res = []
    res.append(f'BYE sip:{sip_cfg["local_ip"]}:{sip_cfg["local_port"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {sip_cfg["local_ip"]}:{sip_cfg["local_port"]};branch={sip_cfg["branch"]}')
    res.append('Max-Forwards: 70')
    res.append(f'To: "{sip_cfg["to_user"]}" <sip:{sip_cfg["username"]}@{sip_cfg["sip_server_addr"]}>') # tag?
    res.append(f'From: <sip:{sip_cfg["username"]}@{sip_cfg["local_ip"]}>;tag={sip_cfg["tag"]}')
    res.append(f'Call-ID: {call_id}')
    res.append(f'CSeq: {sip_cfg["cseq"]} BYE')
    res.append('User-Agent: PythonScript')
    res.append('Content-Length: 0')

    return '\r\n'.join(res)



if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((sip_cfg['local_ip'], sip_cfg['local_port']))
    sock.settimeout(5)

    sdp = create_sdp()
    call_id = hashlib.md5(f"{sip_cfg['call_id']},{time.time()}".encode()).hexdigest()

    print("[+] Sent initial REGISTER")
    data_to_send = create_register_header().encode()
    print('sending initial data:\n', str(data_to_send).replace('\\r\\n', '\n'))
    sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))

    try:
        data, _ = sock.recvfrom(4096)
        response = data.decode()
        print("[<<] REGISTER response:\n", response)

        if "401 Unauthorized" not in response:
            print("[-] Unexpected response. Exiting")
            sock.close()
            exit()
        auth_params = extract_auth_params(response)
        if not auth_params:
            print("[-] Failed to extract nonce/realm")
            sock.close()
            exit()

        nonce = auth_params['nonce']
        realm = auth_params['realm']
        opaque = auth_params['opaque']
        sip_cfg['cseq'] += 1
        print("[+] Sending REGISTER with auth...")
        data_to_send = create_register_header(nonce, realm).encode()
        print('sending data:\n', str(data_to_send).replace('\\r\\n', '\n'))
        sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))
        data, _ = sock.recvfrom(4096)
        if "200 OK" not in data.decode():
            print('auth register answer:', data.decode())
            print("[-] REGISTER failed")
            sock.close()
            exit()
        print("[V] REGISTER successful")
        sip_cfg['cseq'] += 1

        print("[-] Sending INVITE...")
        data_to_send = create_invite_header(nonce, realm).encode()
        print("sending invite data:\n", str(data_to_send).replace('\\r\\n', '\n'))
        sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))
        data, _ = sock.recvfrom(4096)
        print("[<<] INVITE response:\n", data.decode())

        time.sleep(10)
        print("[+] Sending BYE ...")
        data_to_send = create_bye_header().encode()
        print("sending BYE data:\n", str(data_to_send).replace('\\r\\n', '\n'))
        sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))

    except socket.timeout:
        print("[-] No response from server")
    finally:
        sock.close()