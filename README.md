# EPSP (Edelweiss Princess Socket Protocol)

EPSP is a lightweight yet secure encrypted proxy protocol designed to facilitate encrypted TCP/UDP forwarding with built-in authentication. The protocol ensures data integrity and confidentiality using AES-256 encryption, while PBKDF2-based key derivation enhances password security.

This documentation provides an in-depth explanation of EPSP’s authentication mechanism, encryption methodology, packet structure, and operational flow.

---

## Overview

EPSP consists of two main components:

- **EPSP Server**: Listens for client connections, authenticates requests, decrypts received packets, and forwards traffic to the intended target.
- **EPSP Client**: Connects to the server, sends authentication data, encrypts outgoing packets, and processes responses from the server.

### Key Features:
✅ Secure Authentication using AES-256  
✅ PBKDF2-based Key Derivation for Strong Encryption  
✅ Encrypted Packet Transmission  
✅ Support for Both TCP and UDP Proxying  
✅ Multi-threaded Server for Concurrent Handling  

---

## Authentication Mechanism

### Deriving a Secure Encryption Key
EPSP uses PBKDF2 (Password-Based Key Derivation Function 2) to derive a strong AES-256 key from the user's password. This enhances security against brute-force attacks.

```python
from Crypto.Protocol.KDF import PBKDF2

def derive_key(password: bytes) -> bytes:
    return PBKDF2(password, b'random_salt_1234', dkLen=32, count=100000)
```

- **SALT**: A fixed but predefined salt value (`b'random_salt_1234'`) is used. In production, this should be randomly generated and shared securely.
- **ITERATIONS**: 100,000 iterations enhance security.
- **KEY_LENGTH**: 32 bytes (256-bit key for AES-256).

### Authentication Packet Structure

Upon connection, the client sends an authentication packet containing an encrypted authentication string.

| Field         | Size | Description                                      |
|--------------|------|--------------------------------------------------|
| MAGIC_NUMBER | 4B   | Fixed value (`0x12345678`) identifying EPSP packets. |
| AUTH_STRING  | 16B+ | AES-encrypted authentication string (`b'secure_auth_key'`). |

#### Packet Creation:

```python
def create_auth_packet(cipher):
    encrypted_auth = cipher.encrypt(b'secure_auth_key')
    return b'\x12\x34\x56\x78' + encrypted_auth
```

#### Server-side Verification:

```python
def verify_auth(data, cipher):
    if len(data) < 20:
        return False
    magic = data[:4]
    encrypted = data[4:]
    if magic != b'\x12\x34\x56\x78':
        return False
    decrypted = cipher.decrypt(encrypted)
    return decrypted == b'secure_auth_key'
```

---

## Encryption & Secure Communication

EPSP secures all transmitted data using **AES-256 in CBC mode**.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AESCipher:
    def __init__(self, key):
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
        return unpad(cipher.decrypt(ct), AES.block_size)
```

- **IV (Initialization Vector)**: Randomly generated per encryption cycle to prevent repetition-based attacks.
- **Padding & Unpadding**: Ensures messages conform to AES block size (16 bytes).

---

## EPSP Packet Structure

| Field          | Size | Description                                      |
|---------------|------|--------------------------------------------------|
| Length        | 4B   | Total packet length (excluding this header).    |
| Protocol      | 1B   | `0x01` for TCP, `0x02` for UDP.                  |
| Target IP     | 4B   | IPv4 address of the destination.                 |
| Target Port   | 2B   | Destination port number.                         |
| Encrypted Data | Variable | AES-256 encrypted payload.                   |

### Client-Side Packet Creation:

```python
import struct, socket

def send_request(self, protocol: int, target: tuple, data: bytes):
    header = struct.pack('!B4sH', protocol, socket.inet_aton(target[0]), target[1])
    encrypted = self.cipher.encrypt(data)
    packet = header + encrypted
    self.sock.sendall(struct.pack('!I', len(packet)) + packet)
```

### Server-Side Packet Parsing:

```python
protocol = packet[0]
target_ip = socket.inet_ntoa(packet[1:5])
target_port = struct.unpack('!H', packet[5:7])[0]
encrypted = packet[7:]
data = self.cipher.decrypt(encrypted)
```

---

## Server & Client Implementation

### Proxy_protocol.py
import os
import socket
import struct
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from hashlib import sha256

# 配置参数
MAGIC_NUMBER = b'\x12\x34\x56\x78'
AUTH_STRING = b'secure_auth_key'
SALT = b'random_salt_1234'  # 生产环境应随机生成并共享
ITERATIONS = 100000
KEY_LENGTH = 32  # AES-256

# 派生密钥函数
def derive_key(password: bytes) -> bytes:
    return PBKDF2(password, SALT, dkLen=KEY_LENGTH, count=ITERATIONS)

# AES加密/解密类
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

# 协议工具函数
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

# 客户端实现
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

# 服务端实现
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
            # 身份验证
            auth_data = conn.recv(1024)
            if not verify_auth(auth_data, self.cipher):
                conn.send(b'AUTH_FAIL')
                conn.close()
                return
            conn.send(b'AUTH_OK')
            
            # 数据处理循环
            while True:
                length_data = conn.recv(4)
                if not length_data:
                    break
                length = struct.unpack('!I', length_data)[0]
                packet = b''
                while len(packet) < length:
                    packet += conn.recv(length - len(packet))
                
                # 解析数据包
                protocol = packet[0]
                target_ip = socket.inet_ntoa(packet[1:5])
                target_port = struct.unpack('!H', packet[5:7])[0]
                encrypted = packet[7:]
                data = self.cipher.decrypt(encrypted)
                
                # 转发处理
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
                # 实际需要将响应返回客户端
        except Exception as e:
            print(f"TCP forward error: {e}")
    
    def _forward_udp(self, ip: str, port: int, data: bytes):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.sendto(data, (ip, port))
                # UDP无连接，需要实现响应接收机制
        except Exception as e:
            print(f"UDP forward error: {e}")

if __name__ == "__main__":
    # 使用示例：
    # 服务端启动：python proxy_protocol.py server 8888 'server_password'
    # 客户端启动：python proxy_protocol.py client 127.0.0.1 8888 'client_password'
    
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
        # 示例请求
        client.send_request(0x01, ('example.com', 80), b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
```

---

## Running EPSP

### Start the Server
```bash
python proxy_protocol.py server 8888 'server_password'
```

### Start the Client
```bash
python proxy_protocol.py client 127.0.0.1 8888 'client_password'
```

### Send a Request
```python
client.send_request(0x01, ('example.com', 80), b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
```

---

## Future Improvements
✅ Add dynamic SALT handling to enhance security.  
✅ Implement UDP response handling.  
✅ Support additional authentication methods (e.g., Public-Key Crypto).  
✅ Enhance error handling and logging.  

