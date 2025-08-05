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
    'tag_from': '',
    'tag_to': '',
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
    res.append(f'From: <sip:{sip_cfg["username"]}@{sip_cfg["sip_server_addr"]}>;tag={sip_cfg["tag_from"]}')
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
    res.append(f'From: <sip:{sip_cfg["username"]}@{sip_cfg["sip_server_addr"]}>;tag={sip_cfg["tag_from"]}')
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
    res.append(f'BYE sip:{sip_cfg["sip_server_addr"]}:{sip_cfg["sip_server_port"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {sip_cfg["local_ip"]}:{sip_cfg["local_port"]};branch={sip_cfg["branch"]}')
    res.append('Max-Forwards: 70')
    res.append(f'To: <sip:{sip_cfg["to_user"]}@{sip_cfg["sip_server_addr"]}>') # tag?
    res.append(f'From: <sip:{sip_cfg["username"]}@{sip_cfg["local_ip"]}>;tag={sip_cfg["tag_from"]}')
    res.append(f'Call-ID: {call_id}')
    res.append(f'CSeq: {sip_cfg["cseq"]} BYE')
    res.append('User-Agent: PythonScript')
    res.append('Content-Length: 0')

    return '\r\n'.join(res)


def create_ack_header():
    pass


def get_answer_type(answer_data):
    code_types = {
        '100 Trying': ['continue', 'info', 'wait next'],
        '180 Ringing': ['continue', 'info', 'wait next'],
        '181 Call Is Being Forwarded': ['continue', 'info', 'wait next'],
        '182 Queued': ['continue', 'info', 'wait next'],
        '183 Session Progress': ['continue', 'info', 'wait next'],
        
        '200 OK': ['end', 'success', 'need ACK'],
        '202 Accepted': ['end', 'success', 'need ACK'],
        '204 No Notification': ['end', 'success', 'need ACK'],
        
        '300 Multiple Choices': ['end', 'success', 'need alternative'],
        '301 Moved Permanently': ['end', 'success', 'need alternative'],
        '302 Moved Temporarily': ['end', 'success', 'need alternative'],
        '305 Use Proxy': ['end', 'success', 'need proxy'],
        '380 Alternative Service': ['end', 'success', 'need alternative'],

        '400 Bad Request': ['end', 'error', 'stop'],
        '401 Unauthorized': ['end', 'error', 'stop'],
        '403 Forbidden': ['end', 'error', 'stop'],
        '404 Not Found': ['end', 'error', 'stop'],
        '405 Method Not Allowed': ['end', 'error', 'stop'],
        '406 Not Acceptable': ['end', 'error', 'stop'],
        '407 Proxy Authentication Request': ['end', 'error', 'stop'],
        '408 Request Timeout': ['end', 'error', 'stop'],
        '410 Gone': ['end', 'error', 'stop'],
        '415 Unsupported Media Type': ['end', 'error', 'stop'],
        '416 Unsupported URI Scheme': ['end', 'error', 'stop'],
        '420 Bad Extension': ['end', 'error', 'stop'],
        '421 Extension Required': ['end', 'error', 'stop'],
        '423 Interval To Brief': ['end', 'error', 'stop'],
        '480 Temporarily Unavailable': ['end', 'error', 'stop'],
        '481 Call/Transaction Does Not Exist': ['end', 'error', 'stop'],
        '482 Loop Detected': ['end', 'error', 'stop'],
        '483 Too Many Hops': ['end', 'error', 'stop'],
        '484 Address Incomplete': ['end', 'error', 'stop'],
        '485 Ambiguous': ['end', 'error', 'stop'],
        '486 Busy Here': ['end', 'error', 'stop'],
        '487 Request Terminated': ['end', 'error', 'stop'],
        '488 Not Acceptable Here': ['end', 'error', 'stop'],
        '491 Request Pending': ['end', 'error', 'stop'],
        '493 Undecipherable': ['end', 'error', 'stop'],

        '500 Server Internal Error': ['end', 'error', 'stop'],
        '501 Not Implemented': ['end', 'error', 'stop'],
        '502 Bad Gateway': ['end', 'error', 'stop'],
        '503 Service Unavailable': ['end', 'error', 'stop'],
        '504 Server Timeout': ['end', 'error', 'stop'],
        '505 Version Not Supported': ['end', 'error', 'stop'],
        '513 Message Too Large': ['end', 'error', 'stop'],

        '600 Busy Everywhere': ['end', 'error', 'stop'],
        '603 Decline': ['end', 'error', 'stop'],
        '604 Does Not Exist Anywhere': ['end', 'error', 'stop'],
        '606 Not Acceptable': ['end', 'error', 'stop']
    }
    
    for i in code_types.keys():
        if i in answer_data:
            return [i] + code_types[i]
    return [0] + ['unk', 'unk', 'stop']


def parse_answer(answer):
    pass


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((sip_cfg['local_ip'], sip_cfg['local_port']))
    sock.settimeout(8)

    sdp = create_sdp()
    call_id = hashlib.md5(f"{sip_cfg['call_id']},{time.time()}".encode()).hexdigest()
    sip_cfg['tag_from'] = str(random.randint(1000, 9999))

    print("[+] Sent initial REGISTER")
    data_to_send = create_register_header().encode()
    print('sending initial data:\n', str(data_to_send).replace('\\r\\n', '\n'))
    sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))

    try:
        while(True):
            data, _ = sock.recvfrom(1500)
            response = data.decode()
            print("[<<] response message:\n", response)
            answer_type = get_answer_type(response)

            if answer_type[0] == '401 Unauthorized':
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
                call_id = hashlib.md5(f"{sip_cfg['call_id']},{time.time()}".encode()).hexdigest()
                data_to_send = create_invite_header(nonce, realm).encode()
                print("sending invite data:\n", str(data_to_send).replace('\\r\\n', '\n'))
                sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))
                continue
            
            if answer_type[2] == 'error':
                print(f"[-] Error response {answer_type[0]}. Exiting")
                sock.close()
                exit()
        
            if answer_type[2] == 'unk':
                print(f"[-] Unexpected response {answer_type[0]}. Exiting")
                sock.close()
                exit()
            
            if answer_type[2] == 'success':
                # ACK send logic here
                break
        
            if answer_type[2] == 'continue':
                pass


        time.sleep(5)
        print("[+] Sending BYE ...")
        data_to_send = create_bye_header().encode()
        print("sending BYE data:\n", str(data_to_send).replace('\\r\\n', '\n'))
        sock.sendto(data_to_send, (sip_cfg['sip_server_addr'], sip_cfg['sip_server_port']))

    except socket.timeout:
        print("[-] No response from server (socket timeout)")
    finally:
        sock.close()