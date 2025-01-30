# **EPSP - Encrypted Proxy Secure Protocol**  

EPSP (Encrypted Proxy Secure Protocol) is a lightweight yet secure encrypted proxy protocol designed to facilitate encrypted TCP/UDP forwarding with built-in authentication. The protocol ensures data integrity and confidentiality using AES-256 encryption, while PBKDF2-based key derivation enhances password security.  

This documentation provides an in-depth explanation of EPSP’s authentication mechanism, encryption methodology, packet structure, and operational flow.  

---

## **1. Overview**  
EPSP consists of two main components:  
- **EPSP Server:** Listens for client connections, authenticates requests, decrypts received packets, and forwards traffic to the intended target.  
- **EPSP Client:** Connects to the server, sends authentication data, encrypts outgoing packets, and processes responses from the server.  

### **Key Features:**  
✅ Secure Authentication using AES-256  
✅ PBKDF2-based Key Derivation for Strong Encryption  
✅ Encrypted Packet Transmission  
✅ Support for Both TCP and UDP Proxying  
✅ Multi-threaded Server for Concurrent Handling  

---

## **2. Authentication Mechanism**  

### **Deriving a Secure Encryption Key**  
EPSP uses **PBKDF2** (Password-Based Key Derivation Function 2) to derive a strong **AES-256 key** from the user's password. This enhances security against brute-force attacks.  

```python
def derive_key(password: bytes) -> bytes:
    return PBKDF2(password, SALT, dkLen=KEY_LENGTH, count=ITERATIONS)
```
- **SALT:** A fixed but predefined salt value (`b'random_salt_1234'`) is used. In production, this should be randomly generated and shared securely.  
- **ITERATIONS:** 100,000 iterations enhance security.  
- **KEY_LENGTH:** 32 bytes (256-bit key for AES-256).  

### **Authentication Packet Structure**  
Upon connection, the client sends an **authentication packet** containing an encrypted authentication string.  

| Field          | Size | Description |  
|---------------|------|-------------|  
| `MAGIC_NUMBER`  | 4B   | Fixed value (`0x12345678`) identifying EPSP packets. |  
| `AUTH_STRING`  | 16B+ | AES-encrypted authentication string (`b'secure_auth_key'`). |  

**Packet Creation:**  
```python
def create_auth_packet(cipher: AESCipher) -> bytes:
    encrypted_auth = cipher.encrypt(AUTH_STRING)
    return MAGIC_NUMBER + encrypted_auth
```

**Server-side Verification:**  
```python
def verify_auth(data: bytes, cipher: AESCipher) -> bool:
    if len(data) < 20:
        return False
    magic = data[:4]
    encrypted = data[4:]
    if magic != MAGIC_NUMBER:
        return False
    decrypted = cipher.decrypt(encrypted)
    return decrypted == AUTH_STRING
```

---

## **3. Encryption & Secure Communication**  

### **AES-256 Encryption (CBC Mode)**  
EPSP secures all transmitted data using **AES-256 in CBC mode**.  

```python
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, data: bytes) -> bytes:
        iv = get_random_bytes(16)  # Generate a new IV for each message
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return iv + ct_bytes  # Prepend IV to ciphertext
    
    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]  # Extract IV
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
```
- **IV (Initialization Vector)** is randomly generated per encryption cycle to prevent repetition-based attacks.  
- **Padding & Unpadding** ensures that messages conform to AES block size (16 bytes).  

---

## **4. EPSP Packet Structure**  

| Field          | Size  | Description |  
|---------------|-------|-------------|  
| `Length`       | 4B    | Total packet length (excluding this header). |  
| `Protocol`     | 1B    | `0x01` for TCP, `0x02` for UDP. |  
| `Target IP`    | 4B    | IPv4 address of the destination. |  
| `Target Port`  | 2B    | Destination port number. |  
| `Encrypted Data` | Variable | AES-256 encrypted payload. |  

**Client-Side Packet Creation:**  
```python
def send_request(self, protocol: int, target: tuple, data: bytes):
    header = struct.pack('!B4sH', protocol, socket.inet_aton(target[0]), target[1])
    encrypted = self.cipher.encrypt(data)
    packet = header + encrypted
    self.sock.sendall(struct.pack('!I', len(packet)) + packet)
```

**Server-Side Packet Parsing:**  
```python
protocol = packet[0]
target_ip = socket.inet_ntoa(packet[1:5])
target_port = struct.unpack('!H', packet[5:7])[0]
encrypted = packet[7:]
data = self.cipher.decrypt(encrypted)
```

---

## **5. Server & Client Implementation**  

### **EPSP Server**  
The EPSP server listens for incoming connections, verifies authentication, and relays traffic.  

```python
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

### **EPSP Client**  
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

## **6. Running EPSP**  

### **Start the Server**  
```bash
python proxy_protocol.py server 8888 'server_password'
```

### **Start the Client**  
```bash
python proxy_protocol.py client 127.0.0.1 8888 'client_password'
```


---

## **7. Future Improvements**  
✅ Add dynamic SALT handling to enhance security.  
✅ Implement UDP response handling.  
✅ Support additional authentication methods (e.g., Public-Key Crypto).  
✅ Enhance error handling and logging.  

---
