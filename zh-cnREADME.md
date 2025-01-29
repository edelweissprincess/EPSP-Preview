# 雪绒花安全通信协议（Edelweiss Princess Socket Protocol, EPSP）

雪绒花安全通信协议（EPSP）是一种轻量级且安全的加密代理协议，旨在实现加密的 TCP/UDP 转发，并内置身份验证机制。该协议使用 AES-256 加密技术确保数据完整性和机密性，同时采用基于 PBKDF2 的密钥派生方法增强密码安全性。

本文档详细介绍 EPSP 的身份验证机制、加密方法、数据包结构和运行流程。

---

## 概述

EPSP 由两个主要组件组成：

- **EPSP 服务器**：监听客户端连接，验证请求，解密接收的数据包，并将流量转发到目标地址。
- **EPSP 客户端**：连接服务器，发送身份验证数据，加密发送的数据包，并处理服务器的响应。

### 主要特性：

✅ 采用 AES-256 进行安全认证\
✅ 基于 PBKDF2 的密钥派生，提供强加密\
✅ 加密的数据包传输\
✅ 支持 TCP 和 UDP 代理\
✅ 多线程服务器，支持并发处理

---

## 身份验证机制

### 生成安全加密密钥

EPSP 使用 PBKDF2（基于密码的密钥派生函数 2）从用户密码派生一个强大的 AES-256 密钥，从而增强抗暴力破解能力。

```python
from Crypto.Protocol.KDF import PBKDF2

def derive_key(password: bytes) -> bytes:
    return PBKDF2(password, b'random_salt_1234', dkLen=32, count=100000)
```

- **SALT（盐值）**：固定的预定义盐值（`b'random_salt_1234'`），实际应用中应随机生成并安全共享。
- **迭代次数**：100,000 次，提高安全性。
- **密钥长度**：32 字节（AES-256 需要 256 位密钥）。

### 身份验证数据包结构

客户端连接后，发送包含加密身份验证字符串的身份验证数据包。

| 字段         | 大小 | 描述                                               |
| ------------ | ---- | -------------------------------------------------- |
| MAGIC\_NUMBER | 4B   | 固定值（`0x12345678`），用于识别 EPSP 数据包。       |
| AUTH\_STRING  | 16B+ | 经过 AES 加密的身份验证字符串（`b'secure_auth_key'`）。 |

#### 数据包创建：

```python
def create_auth_packet(cipher):
    encrypted_auth = cipher.encrypt(b'secure_auth_key')
    return b'\x12\x34\x56\x78' + encrypted_auth
```

#### 服务器端验证：

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

## 加密与安全通信

EPSP 使用 **AES-256 CBC 模式** 加密所有传输数据。

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

- **IV（初始化向量）**：每次加密时随机生成，以防止重放攻击。
- **填充/去填充**：确保消息符合 AES 块大小（16 字节）。

---

## EPSP 数据包结构

| 字段          | 大小     | 描述                                    |
| ------------- | -------- | --------------------------------------- |
| 长度          | 4B       | 数据包总长度（不包括此头部）。         |
| 协议          | 1B       | `0x01` 表示 TCP，`0x02` 表示 UDP。     |
| 目标 IP      | 4B       | 目标地址的 IPv4 地址。                  |
| 目标端口      | 2B       | 目标端口号。                            |
| 加密数据      | 可变     | 使用 AES-256 加密的负载数据。          |

### 客户端数据包创建：

```python
import struct, socket

def send_request(self, protocol: int, target: tuple, data: bytes):
    header = struct.pack('!B4sH', protocol, socket.inet_aton(target[0]), target[1])
    encrypted = self.cipher.encrypt(data)
    packet = header + encrypted
    self.sock.sendall(struct.pack('!I', len(packet)) + packet)
```

### 服务器端数据包解析：

```python
protocol = packet[0]
target_ip = socket.inet_ntoa(packet[1:5])
target_port = struct.unpack('!H', packet[5:7])[0]
encrypted = packet[7:]
data = self.cipher.decrypt(encrypted)
```

---

## 服务器与客户端实现

### EPSP 服务器

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
        print(f"服务器监听端口 {self.port}")
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self._handle_client, args=(conn,)).start()
```

---

## 未来改进方向

✅ 增加动态 SALT 处理以提高安全性\
✅ 实现 UDP 响应处理\
✅ 支持额外的身份验证方法（如公钥加密）\
✅ 增强错误处理和日志记录
