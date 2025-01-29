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

### EPSP Server

The EPSP server listens for incoming connections, verifies authentication, and relays traffic.

```python
import threading, socket

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
```

### EPSP Client

The EPSP client initiates a connection to the server and sends encrypted requests.

```python
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

