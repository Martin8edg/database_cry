try:
    from dilithium_py.ml_dsa import ML_DSA_44
except ImportError:
    ML_DSA_44 = None

try:
    from kyber_py.ml_kem import ML_KEM_512 
except ImportError:
    ML_KEM_512 = None


class LatticeCrypto:
    @staticmethod
    def is_available() -> bool:
        return ML_DSA_44 is not None and ML_KEM_512 is not None
    
    @staticmethod
    def generate_signing_keypair() -> tuple:
        if not LatticeCrypto.is_available():
            raise ImportError("后量子密码学库未安装")
        
        pk, sk = ML_DSA_44.keygen()
        return pk, sk

    @staticmethod
    def sign_message(sk: bytes, message: bytes) -> bytes:
        if not LatticeCrypto.is_available():
            raise ImportError("后量子密码学库未安装")
        
        return ML_DSA_44.sign(sk, message)

    @staticmethod
    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        if not LatticeCrypto.is_available():
            raise ImportError("后量子密码学库未安装")
        
        try:
            return ML_DSA_44.verify(pk, message, signature)
        except Exception:
            return False

    @staticmethod
    def kem_keygen() -> tuple:
        if not LatticeCrypto.is_available():
            raise ImportError("后量子密码学库未安装")
        
        pk, sk = ML_KEM_512.keygen()
        return pk, sk
        
    @staticmethod
    def kem_encapsulate(pk: bytes) -> tuple:
        if not LatticeCrypto.is_available():
            raise ImportError("后量子密码学库未安装")
        
        shared_secret, ciphertext = ML_KEM_512.encaps(pk)
        return ciphertext, shared_secret
        
    @staticmethod
    def kem_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
        if not LatticeCrypto.is_available():
            raise ImportError("后量子密码学库未安装")
        
        return ML_KEM_512.decaps(sk, ciphertext)