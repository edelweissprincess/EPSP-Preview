#EPSP - 加密代理安全协议（中文版本）
EPSP（Encrypted Proxy Secure Protocol）是一种轻量级但安全的加密代理协议，旨在通过内置身份验证机制进行加密 TCP/UDP 转发，确保数据的机密性和完整性。该协议采用 AES-256 加密，并使用 PBKDF2 进行密钥派生，以增强安全性。

先详细介绍 EPSP 的认证机制、加密方法、数据包结构和运行流程。

1. 概述
EPSP 由两个主要组件组成：
EPSP 服务器（EPSP Server）：监听客户端连接，进行身份验证，解密接收的数据包，并将流量转发至目标地址。
EPSP 客户端（EPSP Client）：与服务器建立连接，发送认证数据，对流量进行加密，并处理服务器的响应数据。
主要特性：
✅ 采用 AES-256 进行安全认证
✅ 使用 PBKDF2 派生密钥，增强加密安全性
✅ 传输数据端到端加密
✅ 支持 TCP 和 UDP 代理
✅ 多线程服务器，支持并发连接

2. 身份验证机制
安全加密密钥的派生
EPSP 采用 PBKDF2（基于密码的密钥派生函数 2）从用户密码派生 AES-256 加密密钥，以增强防暴力破解能力。

python
复制
编辑
def derive_key(password: bytes) -> bytes:
    return PBKDF2(password, SALT, dkLen=KEY_LENGTH, count=ITERATIONS)
SALT（盐值）：一个固定的预定义盐值（如 b'random_salt_1234'）。在生产环境中应随机生成并安全存储。
ITERATIONS（迭代次数）：使用 100,000 次迭代，提高安全性。
KEY_LENGTH（密钥长度）：32 字节（AES-256 需要 256 位密钥）。
身份验证数据包结构
客户端连接服务器后，会发送一个 身份验证数据包，其中包含加密的身份验证字符串。

字段	大小	说明
MAGIC_NUMBER	4B	固定值 0x12345678，用于标识 EPSP 数据包
AUTH_STRING	16B+	AES 加密的身份验证字符串 (b'secure_auth_key')
客户端创建身份验证数据包：

python
复制
编辑
def create_auth_packet(cipher: AESCipher) -> bytes:
    encrypted_auth = cipher.encrypt(AUTH_STRING)
    return MAGIC_NUMBER + encrypted_auth
服务器验证身份信息：

python
复制
编辑
def verify_auth(data: bytes, cipher: AESCipher) -> bool:
    if len(data) < 20:
        return False
    magic = data[:4]
    encrypted = data[4:]
    if magic != MAGIC_NUMBER:
        return False
    decrypted = cipher.decrypt(encrypted)
    return decrypted == AUTH_STRING
3. 数据加密与通信安全
AES-256 加密（CBC 模式）
EPSP 采用 AES-256 CBC 模式 进行数据加密，保证数据安全传输。

python
复制
编辑
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, data: bytes) -> bytes:
        iv = get_random_bytes(16)  # 每次加密生成新的 IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return iv + ct_bytes  # 将 IV 附加到密文前

    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]  # 取出 IV
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
IV（初始化向量） 每次加密时随机生成，防止重复攻击。
填充（Padding） 使数据满足 AES 16 字节的块大小要求。
4. EPSP 数据包格式
字段	大小	说明
Length	4B	数据包总长度（不包含此头部）
Protocol	1B	0x01 表示 TCP，0x02 表示 UDP
Target IP	4B	目标 IPv4 地址
Target Port	2B	目标端口号
Encrypted Data	变量	AES-256 加密的有效载荷
客户端创建数据包：

python
复制
编辑
def send_request(self, protocol: int, target: tuple, data: bytes):
    header = struct.pack('!B4sH', protocol, socket.inet_aton(target[0]), target[1])
    encrypted = self.cipher.encrypt(data)
    packet = header + encrypted
    self.sock.sendall(struct.pack('!I', len(packet)) + packet)
服务器解析数据包：

python
复制
编辑
protocol = packet[0]
target_ip = socket.inet_ntoa(packet[1:5])
target_port = struct.unpack('!H', packet[5:7])[0]
encrypted = packet[7:]
data = self.cipher.decrypt(encrypted)
5. EPSP 服务器与客户端实现
EPSP 服务器
服务器监听连接，验证身份并转发流量。

python
复制
编辑
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
EPSP 客户端
客户端连接服务器并发送请求。

python
复制
编辑
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
            raise ConnectionError("身份验证失败")
6. 运行 EPSP
启动服务器
bash
复制
编辑
python proxy_protocol.py server 8888 'server_password'
启动客户端
bash
复制
编辑
python proxy_protocol.py client 127.0.0.1 8888 'client_password'
发送请求
python
复制
编辑
client.send_request(0x01, ('example.com', 80), b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
7. 未来改进
✅ 增强盐值管理，防止密钥重用风险
✅ 完善 UDP 代理支持
✅ 添加基于公钥加密的身份验证方式
✅ 增强日志记录和错误处理
