# DatabaseCry - 本地数据库加密系统

基于[QSP](https://github.com/ARS4EVER/QSP)加密逻辑构建的本地数据库加密工具，采用模块化架构设计。

## 项目架构

```
database_cry/
├── main.py                    # 主入口文件
├── gui.py                     # Tkinter图形界面
├── database_handler.py        # 数据库文件处理模块
├── crypto/                    # 加密模块（模块化拆分）
│   ├── __init__.py            # 模块导出
│   ├── gf256.py               # GF(256)有限域运算
│   ├── aes_gcm.py             # AES-GCM-256加密
│   └── lattice.py             # 后量子密码学封装
├── .vault/                    # 密钥存储目录（运行时自动创建）
├── databases/                 # 加密数据库存储目录（运行时自动创建）
└── README.md                  # 本文档
```

## 代码引用关系

### 与QSP项目的代码继承关系

本项目的核心加密逻辑全部引用自QSP项目，以下是详细的引用映射：

| DatabaseCry模块 | QSP源文件 | 引用内容 |
|----------------|----------|----------|
| `crypto/gf256.py` | `src/secret_sharing/gf256.py` | GF(256)有限域运算 |
| `crypto/aes_gcm.py` | `src/app/vault_crypto.py` | AES-GCM加密、密钥派生、密码验证 |
| `crypto/lattice.py` | `src/crypto_lattice/wrapper.py` | ML-KEM/ML-DSA后量子算法 |

---

## 模块详解

### 1. GF(256)有限域运算

**文件**: `crypto/gf256.py`

**引用来源**: `src/secret_sharing/gf256.py`

**核心代码**:

```python
# 查表法实现O(1)复杂度的有限域运算
EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256

def gf_mul(a: int, b: int) -> int:
    """GF(256)乘法"""
    if a == 0 or b == 0: return 0
    return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]

def gf_div(a: int, b: int) -> int:
    """GF(256)除法"""
    if a == 0: return 0
    if b == 0: raise ZeroDivisionError("GF(256) division by zero")
    return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b]) % 255]
```

**功能说明**:
- 使用预计算的指数表和对数表实现常数时间复杂度的有限域运算
- 基于不可约多项式 `x^8 + x^4 + x^3 + x + 1` (0x11B)
- 是Shamir秘密分享算法的数学基础

---

### 2. AES-GCM-256加密器

**文件**: `crypto/aes_gcm.py`

**引用来源**: `src/app/vault_crypto.py`

**核心代码**:

```python
class AesGcmCrypto:
    MAGIC_VERIFIER = b"QSP_VAULT_MAGIC_VERIFIER"
    
    def _derive_key(self) -> bytes:
        """PBKDF2-HMAC-SHA256密钥派生"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,           # 256位密钥
            salt=self.salt,
            iterations=100000,   # 防暴力破解
            backend=default_backend()
        )
        return kdf.derive(self.password)
    
    def _verify_or_create_authenticator(self):
        """HMAC-SHA256密码验证"""
        current_mac = hmac.new(self.key, self.MAGIC_VERIFIER, hashlib.sha256).digest()
        
        if os.path.exists(self.verifier_path):
            with open(self.verifier_path, "rb") as f:
                stored_mac = f.read()
            
            if not hmac.compare_digest(current_mac, stored_mac):
                raise PasswordAuthError("密码错误，拒绝解锁！")
        else:
            self._atomic_write(self.verifier_path, current_mac)
    
    def encrypt_data(self, data: bytes) -> bytes:
        """加密数据，返回: Nonce[12] + Ciphertext + Tag[16]"""
        nonce = os.urandom(12)
        ciphertext_with_tag = self.aesgcm.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext_with_tag
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """解密数据，包含GCM完整性验证"""
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
```

**安全特性**:

| 特性 | 实现方式 |
|------|----------|
| 密钥派生 | PBKDF2-HMAC-SHA256, 100,000次迭代 |
| 对称加密 | AES-GCM-256 |
| 密码验证 | HMAC-SHA256 |
| 原子写盘 | tmp文件 + fsync + rename |
| 内存自毁 | 异常时清空密钥并触发GC |

---

### 3. 后量子密码学

**文件**: `crypto/lattice.py`

**引用来源**: `src/crypto_lattice/wrapper.py`

**核心代码**:

```python
class LatticeCrypto:
    # ML-KEM-512 密钥交换
    @staticmethod
    def kem_keygen() -> tuple:
        """生成密钥对"""
        pk, sk = ML_KEM_512.keygen()
        return pk, sk
    
    @staticmethod
    def kem_encapsulate(pk: bytes) -> tuple:
        """封装密钥（Client端）"""
        shared_secret, ciphertext = ML_KEM_512.encaps(pk)
        return ciphertext, shared_secret
    
    @staticmethod
    def kem_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
        """解封装密钥（Server端）"""
        return ML_KEM_512.decaps(sk, ciphertext)
    
    # ML-DSA-44 数字签名
    @staticmethod
    def sign_message(sk: bytes, message: bytes) -> bytes:
        """签名消息"""
        return ML_DSA_44.sign(sk, message)
    
    @staticmethod
    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        """验证签名"""
        return ML_DSA_44.verify(pk, message, signature)
```

**算法参数**:

| 算法 | 密钥大小 | 输出大小 | 安全性 |
|------|----------|----------|--------|
| ML-KEM-512 | 公钥800B, 私钥1632B | 密文768B, 共享密钥32B | NIST PQC标准 |
| ML-DSA-44 | 公钥1312B, 私钥2420B | 签名2420B | NIST PQC标准 |

---

### 4. 数据库处理器

**文件**: `database_handler.py`

**核心功能**:
- 加密数据库文件并保存元数据
- 解密数据库文件并验证完整性
- 管理加密数据库列表

**加密文件格式**:

```
┌──────────────────────────────────────────────────────────────┐
│                    加密文件格式 (.enc)                        │
├──────────────────────────────────────────────────────────────┤
│ MAGIC_HEADER (14字节)    │ "DBENCRYPT_V1"                   │
├──────────────────────────┼───────────────────────────────────┤
│ 元数据长度 (4字节)        │ JSON元数据长度（大端序）           │
├──────────────────────────┼───────────────────────────────────┤
│ JSON元数据 (变长)         │ {"db_name": "...", "checksum": "..."}│
├──────────────────────────┼───────────────────────────────────┤
│ 加密数据 (变长)           │ Nonce[12] + Ciphertext + Tag[16] │
└──────────────────────────┴───────────────────────────────────┘
```

---

### 5. 图形界面

**文件**: `gui.py`

**功能模块**:
- 金库解锁/创建界面
- 数据库加密/解密操作
- 数据库列表管理
- 操作日志显示

---

## 安装依赖

```bash
cd database_cry
pip install cryptography
```

## 使用方法

### 启动程序

```bash
python main.py
```

### 操作流程

1. **首次使用**：设置主密码创建金库
2. **解锁金库**：输入主密码解锁
3. **加密数据库**：选择数据库文件并设置名称
4. **解密数据库**：选择已加密的数据库并保存

## 目录结构说明

```
database_cry/                    # 项目根目录
├── main.py                      # 启动入口
├── gui.py                       # GUI界面实现
├── database_handler.py          # 数据库处理逻辑
├── crypto/                      # 加密模块目录
│   ├── __init__.py              # 模块导出声明
│   ├── gf256.py                 # GF(256)有限域运算
│   ├── aes_gcm.py               # AES-GCM-256加密器
│   └── lattice.py               # 后量子密码学封装
├── .vault/                      # 密钥存储（自动创建）
│   ├── .aes_salt                # 加密盐值
│   └── .aes_verifier            # 密码验证器
└── databases/                   # 加密数据库存储（自动创建）
    └── *.enc                    # 加密的数据库文件
```

## 引用关系图

```
┌─────────────────────────────────────────────────────────────┐
│                      QSP 项目 (源码)                        │
├─────────────────────────────────────────────────────────────┤
│  src/secret_sharing/gf256.py        │  src/app/vault_crypto.py  │  src/crypto_lattice/wrapper.py  │
└────────────────────┬─────────────────┴──────────┬───────────┴───────────────────┬────────────────────┘
                     │                            │                               │
                     ▼                            ▼                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                         DatabaseCry 项目 (继承)                                                │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│  crypto/gf256.py                    │  crypto/aes_gcm.py               │  crypto/lattice.py             │
│  ├─ gf_mul()                        │  ├─ AesGcmCrypto                 │  ├─ LatticeCrypto              │
│  └─ gf_div()                        │  ├─ _derive_key()                │  ├─ kem_keygen()               │
│                                     │  ├─ _verify_or_create_auth()     │  ├─ kem_encapsulate()          │
│                                     │  ├─ encrypt_data()               │  ├─ kem_decapsulate()          │
│                                     │  └─ decrypt_data()               │  ├─ sign_message()             │
│                                     │                                  │  └─ verify_signature()         │
└─────────────────────────────────────┴───────────────────────────────────┴───────────────────────┘
                                                  │
                                                  ▼
                                      ┌─────────────────────┐
                                      │  database_handler.py │
                                      │  DatabaseHandler     │
                                      │  ├─ encrypt_database()│
                                      │  ├─ decrypt_database()│
                                      │  └─ list_databases()  │
                                      └─────────────────────┘
                                                  │
                                                  ▼
                                      ┌─────────────────────┐
                                      │       gui.py         │
                                      │  DatabaseCryGUI      │
                                      │  ├─ 解锁/创建金库    │
                                      │  ├─ 加密数据库       │
                                      │  ├─ 解密数据库       │
                                      │  └─ 管理数据库列表   │
                                      └─────────────────────┘
```

## 安全注意事项

1. **密码安全**：请使用强密码（建议≥8位，包含大小写字母、数字、特殊字符）
2. **密钥备份**：`.vault`目录包含加密密钥，建议定期备份
3. **数据备份**：加密前请备份原始数据库文件
4. **内存安全**：程序异常退出时会自动清理内存中的敏感数据

## 许可证

本项目基于QSP项目加密逻辑实现，遵循相关开源协议。

## 参考

- [QSP](https://github.com/ARS4EVER/QSP)
- [NIST后量子密码学标准](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [cryptography库文档](https://cryptography.io/en/latest/)
