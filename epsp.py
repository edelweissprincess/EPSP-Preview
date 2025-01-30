import os
import socket
import struct
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from hashlib import sha256

MAGIC_NUMBER = b'\x12\x34\x56\x78'
AUTH_STRING = b'secure_auth_key'
SALT = b'random_salt_1234'
ITERATIONS = 100000
KEY_LENGTH = 32  # AES-256
def derive_key(password: bytes) -> bytes:
    return PBKDF2(password, SALT, dkLen=KEY_LENGTH, count=ITERATIONS)
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, data: bytes) -> bytes:
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return iv + ct_bytes
    
    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
def create_auth_packet(cipher: AESCipher) -> bytes:
    encrypted_auth = cipher.encrypt(AUTH_STRING)
    return MAGIC_NUMBER + encrypted_auth

def verify_auth(data: bytes, cipher: AESCipher) -> bool:
    if len(data) < 20:
        return False
    magic = data[:4]
    encrypted = data[4:]
    if magic != MAGIC_NUMBER:
        return False
    decrypted = cipher.decrypt(encrypted)
    return decrypted == AUTH_STRING
class ProxyClient:
    def __init__(self, server_ip: str, port: int, password: str):
        self.server_ip = server_ip
        self.port = port
        self.cipher = AESCipher(derive_key(password.encode()))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._connect()
    
    def _connect(self):
        self.sock.connect((self.server_ip, self.port))
        auth_packet = create_auth_packet(self.cipher)
        self.sock.sendall(auth_packet)
        resp = self.sock.recv(1024)
        if resp != b'AUTH_OK':
            raise ConnectionError("Authentication failed")
    
    def send_request(self, protocol: int, target: tuple, data: bytes):
        try:
            header = struct.pack('!B4sH', protocol, 
                               socket.inet_aton(target[0]), target[1])
            encrypted = self.cipher.encrypt(data)
            packet = header + encrypted
            self.sock.sendall(struct.pack('!I', len(packet)) + packet)
        except Exception as e:
            print(f"Send error: {e}")
class ProxyServer:
    def __init__(self, port: int, password: str):
        self.port = port
        self.cipher = AESCipher(derive_key(password.encode()))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._start()
    
    def _start(self):
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen(5)
        print(f"Server listening on port {self.port}")
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self._handle_client, args=(conn,)).start()
    
    def _handle_client(self, conn: socket.socket):
        try:
            auth_data = conn.recv(1024)
            if not verify_auth(auth_data, self.cipher):
                conn.send(b'AUTH_FAIL')
                conn.close()
                return
            conn.send(b'AUTH_OK')
            while True:
                length_data = conn.recv(4)
                if not length_data:
                    break
                length = struct.unpack('!I', length_data)[0]
                packet = b''
                while len(packet) < length:
                    packet += conn.recv(length - len(packet))
                protocol = packet[0]
                target_ip = socket.inet_ntoa(packet[1:5])
                target_port = struct.unpack('!H', packet[5:7])[0]
                encrypted = packet[7:]
                data = self.cipher.decrypt(encrypted)
                if protocol == 0x01:
                    self._forward_tcp(target_ip, target_port, data)
                elif protocol == 0x02:
                    self._forward_udp(target_ip, target_port, data)
                    
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            conn.close()
    
    def _forward_tcp(self, ip: str, port: int, data: bytes):
        try:
            with socket.create_connection((ip, port), timeout=5) as remote:
                remote.send(data)
                response = remote.recv(4096)
        except Exception as e:
            print(f"TCP forward error: {e}")
    
    def _forward_udp(self, ip: str, port: int, data: bytes):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.sendto(data, (ip, port))
        except Exception as e:
            print(f"UDP forward error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage:")
        print("Server: python proxy_protocol.py server [port] [password]")
        print("Client: python proxy_protocol.py client [server_ip] [port] [password]")
        sys.exit(1)
    
    if sys.argv[1] == 'server':
        server = ProxyServer(int(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == 'client':
        client = ProxyClient(sys.argv[2], int(sys.argv[3]), sys.argv[4])
        client.send_request(0x01, ('example.com', 80), b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
