import argparse
import base64
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import socket


GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"


class ScanResult:
    ip = ''
    port = 0
    id = ''
    name = '<unknown>'

    def __init__(self, ip, port, id, name=''):
        self.ip = ip
        self.port = port
        self.id = id
        self.name = name


def send_data(ip, port, data):
    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(args, 'socket_interface') and args.socket_interface:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.socket_interface.encode('ascii'))
    s.sendto(data, (ip, port))
    return s.recv(1024)


def add_pkcs7_padding(data):
    length = 16 - (len(data) % 16)
    padded = data + chr(length) * length
    return padded


def create_cipher(key):
    return Cipher(algorithms.AES(key.encode('utf-8')), modes.ECB(), backend=default_backend())


def decrypt(pack_encoded, key):
    decryptor = create_cipher(key).decryptor()
    pack_decoded = base64.b64decode(pack_encoded)
    pack_decrypted = decryptor.update(pack_decoded) + decryptor.finalize()
    pack_unpadded = pack_decrypted[0:pack_decrypted.rfind(b'}') + 1]
    return pack_unpadded.decode('utf-8')


def decrypt_generic(pack_encoded):
    return decrypt(pack_encoded, GENERIC_KEY)


def encrypt(pack, key):
    encryptor = create_cipher(key).encryptor()
    pack_padded = add_pkcs7_padding(pack)
    pack_encrypted = encryptor.update(bytes(pack_padded, encoding='utf-8')) + encryptor.finalize()
    pack_encoded = base64.b64encode(pack_encrypted)
    return pack_encoded.decode('utf-8')


def encrypt_generic(pack):
    return encrypt(pack, GENERIC_KEY)


def get_param():

    cols = ','.join(f'"{i}"' for i in args.params)
    
    pack = f'{{"cols":[{cols}],"mac":"%s","t":"status"}}' \
            % (args.mac)
    pack_encrypted = encrypt(pack, '5Wx8Za1Cd4Fg7Ij0') # Replace encryption key with own encryption key

    request = '{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"9424b8f55784","uid":0}' \
              % (pack_encrypted) # Replace tcid with own id

    result = send_data("192.168.10.120", 7000, bytes(request, encoding='utf-8')) # Replace ip with ip adress of the unit

    response = json.loads(result)
    
    resultjson = {}

    if response["t"] == "pack":
        pack = response["pack"]

        pack_decrypted = decrypt(pack, '5Wx8Za1Cd4Fg7Ij0') # Replace encryption key with own encryption key
        pack_json = json.loads(pack_decrypted)
    
    for col, dat in zip(pack_json['cols'], pack_json['dat']): resultjson[col] = dat
    print (json.dumps(resultjson))


def set_param():
    kv_list = [i.split('=') for i in args.params]
    errors = [i for i in kv_list if len(i) != 2]

    if len(errors) > 0:
        print(f'Invalid parameters detected: {errors}')
        exit(1)

    print(f'Setting parameters: {", ".join("=".join(i) for i in kv_list)}')

    opts = ','.join(f'"{i[0]}"' for i in kv_list)
    ps = ','.join(i[1] for i in kv_list)

    pack = f'{{"opt":[{opts}],"p":[{ps}],"t":"cmd","sub":"%s"}}' \
                % (args.mac)
    print(pack)
    pack_encrypted = encrypt(pack, '5Wx8Za1Cd4Fg7Ij0') # Replace encryption key with own encryption key

    request = '{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"9424b8f55784","uid":0}' \
              % (pack_encrypted) # Replace tcid with own id

    result = send_data("192.168.10.120", 7000, bytes(request, encoding='utf-8'))

    response = json.loads(result)

    if response["t"] == "pack":
        pack = response["pack"]

        pack_decrypted = decrypt(pack, '5Wx8Za1Cd4Fg7Ij0') # Replace encryption key with own encryption key
        pack_json = json.loads(pack_decrypted)

        if pack_json['r'] != 200:
            print('Failed to set parameter')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_help = True
    parser.add_argument('command', help='You can use the following commands: get, set')
    parser.add_argument('-m', '--mac', help='MAC adress of the subunit')
    if sys.platform == 'linux':
        parser.add_argument('--socket-interface', help='Bind the socket to a specific network interface')
    parser.add_argument('params', nargs='*', default=None, type=str)

    args = parser.parse_args()

    command = args.command.lower()
    if command == 'get':
        if args.params is None or len(args.params) == 0 or args.mac is None:
            print('Error: get command requires a parameter name and -m with mac adress of the subunit')
            exit(1)
        get_param()
    elif command == 'set':
        if args.params is None or len(args.params) == 0 or args.mac is None:
            print('Error: set command requires at least one key=value pair')
            exit(1)
        set_param()
    else:
        print('Error: unknown command "%s"' % args.command)
        exit(1)
