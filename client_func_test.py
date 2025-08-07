import socket
import re
import hashlib
import random
import time


sip_cfg = {
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

register_params = {
    'call_id': '',
    'cseq': 1,
    'sip_server_addr': '10.120.0.127',
    'sip_server_port': 5060,
    'local_ip': '10.120.0.115',
    'local_port': 5066,
    'username': '1000',
    'password': '1000',
    'nonce': '',
    'realm': '',
    'tag_from': ''
}

sip_cfg['contact'] = f'sip:{register_params["username"]}@{register_params["local_ip"]}:{register_params["local_port"]}'
sip_cfg['uri_register'] = f'sip:{register_params["sip_server_addr"]}:{register_params["sip_server_port"]}'
sip_cfg['uri_invite'] = f'sip:{sip_cfg['to_user']}@{register_params["sip_server_addr"]}'


current_auth = {
    'realm': '',
    'nonce': '',
    'cnonce': '',
    'opaque': '',
    'nc': 0,
    'algorithm': 'MD5',
    'response': ''
}

global_vars = {
    'last_answer': '',
    'is_registered': False
}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((register_params['local_ip'], register_params['local_port']))
sock.settimeout(8)


def create_sdp():
    res = []
    res.append('v=0')
    res.append(f'o={register_params["username"]} 0 0 IN IP4 {register_params["local_ip"]}')
    res.append('s=-')
    res.append(f'c=IN IP4 {register_params['local_ip']}')
    res.append('t=0 0')
    res.append('m=audio 8000 RTP/AVP 0')
    res.append('a=rtpmap:0 PCMU/8000')
    return '\r\n'.join(res)


def calculate_response(username, password, realm, method, uri, nonce):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def extract_auth_params(ans):
    auth_line = re.search(r'WWW-Authenticate: Digest (.+)', ans)
    if not auth_line:
        return None
    return dict(re.findall(r'(\w+)="([^"]+)"', auth_line.group(1)))


def create_auth_header(method: str) -> str:
    response = calculate_response(register_params['username'], register_params['password'], current_auth['realm'], 
                                      method, sip_cfg['uri_register'], current_auth['nonce'])
    cnonce = hashlib.md5(f"{register_params['username']}:{current_auth['realm']}:{register_params['password']}".encode()).hexdigest()
    nc = str(sip_cfg['cseq']).zfill(8)
    res = []
    res.append(f'Authorization: Digest username="{register_params['username']}"')
    res.append(f'realm="{current_auth['realm']}"')
    res.append(f'nonce="{current_auth['nonce']}"')
    res.append(f'uri="{sip_cfg["uri_register"]}"')
    res.append(f'response="{response}"')
    # res.append(f'cnonce="{cnonce}"')
    # res.append(f'nc="{nc}"')
    # res.append('qop=auth')
    # res.append(f'opaque="{current_auth['opaque']}"')
    res.append('algorithm=MD5')
    return ','.join(res)


def create_register_header(call_id):
    res = []
    res.append(f'REGISTER sip:{register_params["sip_server_addr"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {register_params["local_ip"]}:{register_params["local_port"]};branch={sip_cfg["branch"]}-reg')
    res.append('Max-Forwards: 70')
    res.append(f'To: <sip:{register_params["username"]}@{register_params["sip_server_addr"]}>')
    res.append(f'From: <sip:{register_params["username"]}@{register_params["sip_server_addr"]}>;tag={register_params["tag_from"]}')
    res.append(call_id)
    res.append(f'CSeq: {register_params["cseq"]} REGISTER')
    res.append(f'Contact: <{sip_cfg["contact"]}>;expires=3600')
    # res.append('Expires: 300')
    # res.append('Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, INFO, MESSAGE')
    # res.append('Supported: replaces')
    res.append('User-Agent: PythonScript')

    if register_params['nonce'] and register_params['realm']:
        print("using auth..")
        auth_header = create_auth_header('REGISTER')
        res.append(auth_header)
        res.append('Content-Length: 0\r\n')
    return '\r\n'.join(res)
    

def create_invite_header():
    res = []
    res.append(f'INVITE {sip_cfg["uri_invite"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {register_params["local_ip"]}:{sip_cfg["local_port"]};branch={sip_cfg["branch"]}')
    res.append('Max-Forwards: 70')
    res.append(f'To: <{sip_cfg["uri_invite"]}>')
    res.append(f'From: <sip:{register_params["username"]}@{register_params["sip_server_addr"]}>;tag={sip_cfg["tag_from"]}')
    res.append(f'Call-ID: {call_id}')
    res.append(f'CSeq: {sip_cfg["cseq"]} INVITE')
    res.append(f'Contact: <{sip_cfg["contact"]}>')
    res.append('Content-Type: application/sdp')

    if current_auth['nonce'] and current_auth['realm']:
        print("using auth..")
        auth_header = create_auth_header('INVITE')
        res.append(auth_header)
        res.append(f'Content-Length: {len(sdp)}\r\n')
        res.append(sdp)
    else:
        res.append(f'Content-Length: {len(sdp)}\r\n')
        res.append(sdp)
    return '\r\n'.join(res)
    

def create_bye_header():
    auth_headers = create_auth_header('BYE')
    res = []
    res.append(f'BYE sip:{register_params["sip_server_addr"]}:{register_params["sip_server_port"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {register_params["local_ip"]}:{sip_cfg["local_port"]};branch={sip_cfg["branch"]}')
    res.append('Max-Forwards: 70')
    res.append(f'To: <sip:{sip_cfg["to_user"]}@{register_params["sip_server_addr"]}>') # tag?
    res.append(f'From: <sip:{register_params["username"]}@{register_params["local_ip"]}>;tag={sip_cfg["tag_from"]}')
    res.append(f'Call-ID: {call_id}')
    res.append(f'CSeq: {sip_cfg["cseq"]} BYE')
    res.append('User-Agent: PythonScript')
    # res.append(auth_headers)
    res.append('Content-Length: 0')

    return '\r\n'.join(res)


def create_ack_header():
    res = []
    res.append(f'ACK sip:{register_params["username"]}@{register_params["local_ip"]}:{register_params["local_port"]} SIP/2.0')
    res.append(f'Via: SIP/2.0/UDP {register_params["sip_server_addr"]}:{register_params["sip_server_port"]}') # rport, branch
    res.append(f'From: <sip:{sip_cfg["to_user"]}@{register_params["sip_server_addr"]}>;tag={sip_cfg["tag_from"]}')
    res.append(f'To: <sip:')

    return '\r\n'.join(res)


def create_ok_answer():
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


def extract_answer_values(answer):
    headers_list = answer.split('\r\n')
    res = {}
    for n, header in enumerate(headers_list):
        if n == 0:
            items = re.split(r'^([A-Z]+)\s(.+)', header)
        else:
            items = re.split(r'^(.+):\s(.+)', header)
        res[items[1]] = items[2]
    return res


def register():
    call_id = hashlib.md5(f"{sip_cfg['call_id']},{time.time()}".encode()).hexdigest()
    register_params['tag_from'] = str(random.randint(1000, 9999))
    
    print('sending initial reg..\n')
    register_params['nonce'] = ''
    register_params['realm'] = ''
    data_to_send = create_register_header(call_id)
    send_sip_message(data_to_send)

    try:
        while(True):
            time.sleep(2)
            answer = receive_sip_message
            global_vars['last_answer'] = answer
            answer_type = get_answer_type(answer)
            if answer_type[0] == '401 Unauthorized':
                register_params['cseq'] += 1
                auth_params = extract_auth_params(answer)
                if not auth_params:
                    print("[-] Failed to extract nonce/realm")
                    sock.close()
                    exit()
                register_params['nonce'] = auth_params['nonce']
                register_params['realm'] = auth_params['realm']
                print('sending auth register..\n')
                data_to_send = create_register_header(call_id)
                send_sip_message(data_to_send)
                time.sleep(1)
                answer = receive_sip_message()
                global_vars['last_answer'] = answer
                answer_type = get_answer_type(answer)
                if '200 OK' not in answer:
                    print("[-] REGISTER failed")
                    sock.close()
                    exit()
                else:
                    print("[V] REGISTER successful\n\n")
                    global_vars['is_registered'] = True
                    break
            else:
                print('unexpected answer')
                sock.close()
                exit()
    except socket.timeout:
        print("[-] No response from server (socket timeout)")


def invite(dest_user):
    pass


def ack():
    pass


def bye():
    pass


def cancel():
    pass


def options():
    pass


def info():
    pass


def prack():
    pass


def update():
    pass


def subscribe():
    pass


def notify():
    pass


def message():
    pass


def refer():
    pass


def publish():
    pass


def send_sip_message(data) -> None:
    print('sending data:\n', str(data).replace('\\r\\n', '\n'), '\n\n')
    sock.sendto(data.encode(), (register_params['sip_server_addr'], register_params['sip_server_port']))


def receive_sip_message():
    data, _ = sock.recvfrom(1500)
    res = data.decode()
    print('answer message:\n', str(res).replace('\\r\\n', '\n'), '\n\n')
    return res


if __name__ == '__main__':
    sdp = create_sdp()
    #call_id = hashlib.md5(f"{sip_cfg['call_id']},{time.time()}".encode()).hexdigest()
    #sip_cfg['tag_from'] = str(random.randint(1000, 9999))

    register()
    
    while(True):
        if global_vars['is_registered']:
            print("[-] Sending initial INVITE...\n")
            current_auth['nonce'] = ''
            current_auth['realm'] = ''
            # call_id = hashlib.md5(f"{sip_cfg['call_id']},{time.time()}".encode()).hexdigest()
            data_to_send = create_invite_header().encode()
            print("sending initial invite data:\n", str(data_to_send).replace('\\r\\n', '\n'))
            sock.sendto(data_to_send, (register_params['sip_server_addr'], register_params['sip_server_port']))
            data, _ = sock.recvfrom(1500)
            answer = data.decode()
            print("[<<] answer message:\n", answer, '\n\n')
            print("[-] Sending auth INVITE...\n")
            auth_params = extract_auth_params(answer)
            current_auth['nonce'] = auth_params['nonce']
            current_auth['realm'] = auth_params['realm']
            sip_cfg['cseq'] += 1
            data_to_send = create_invite_header().encode()
            print("sending initial invite data:\n", str(data_to_send).replace('\\r\\n', '\n'))
            sock.sendto(data_to_send, (register_params['sip_server_addr'], register_params['sip_server_port']))
            continue
        else:
            print('stopping due to register failure')
            sock.close()
            exit()
        
        if answer_type[2] == 'continue':
            print(f'current state: {answer_type[0]}, waiting next message')
            print('answer:', answer)
            continue
        
        
        if answer_type[2] == 'error':
            print(f"[-] Error answer {answer_type[0]}. Exiting")
            sock.close()
            exit()
    
        if answer_type[2] == 'unk':
            print(f"[-] Unexpected answer {answer_type[0]}. Exiting")
            sock.close()
            exit()
        
        if answer_type[2] == 'success':
            data_to_send = create_ack_header().encode()
            print('sending ack data: \n', str(data_to_send).replace('\\r\\n', '\n'))
            sock.sendto(data_to_send, (register_params['sip_server_addr'], register_params['sip_server_port']))
            break


    time.sleep(5)
    print("[+] Sending BYE ...")
    data_to_send = create_bye_header().encode()
    print("sending BYE data:\n", str(data_to_send).replace('\\r\\n', '\n'))
    sock.sendto(data_to_send, (register_params['sip_server_addr'], register_params['sip_server_port']))
