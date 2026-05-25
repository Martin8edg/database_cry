import os
import json
import struct
import hashlib
from datetime import datetime
from typing import Optional, Tuple
from crypto import AesGcmCrypto, CryptoError


class DatabaseHandler:
    MAGIC_HEADER = b"DBENCRYPT_V1"
    CHUNK_SIZE = 64 * 1024
    
    def __init__(self, crypto: AesGcmCrypto, db_dir: str = None):
        self.crypto = crypto
        self.db_dir = db_dir or os.path.join(os.path.dirname(__file__), "databases")
        os.makedirs(self.db_dir, exist_ok=True)
    
    def get_encrypted_path(self, db_name: str) -> str:
        return os.path.join(self.db_dir, f"{db_name}.enc")
    
    def get_meta_path(self, db_name: str) -> str:
        return os.path.join(self.db_dir, f"{db_name}.meta")
    
    def _calculate_checksum(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    
    def encrypt_database(
        self,
        source_path: str,
        db_name: str,
        description: str = ""
    ) -> Tuple[bool, str]:
        try:
            if not os.path.exists(source_path):
                return False, f"源文件不存在: {source_path}"
            
            with open(source_path, "rb") as f:
                original_data = f.read()
            
            original_size = len(original_data)
            
            metadata = {
                "db_name": db_name,
                "original_filename": os.path.basename(source_path),
                "original_size": original_size,
                "original_checksum": self._calculate_checksum(original_data),
                "encrypted_at": datetime.now().isoformat(),
                "description": description,
                "version": "1.0"
            }
            
            encrypted_data = self.crypto.encrypt_data(original_data)
            
            meta_json = json.dumps(metadata, ensure_ascii=False)
            meta_bytes = meta_json.encode('utf-8')
            meta_length = struct.pack('>I', len(meta_bytes))
            
            output_data = (
                self.MAGIC_HEADER +
                meta_length +
                meta_bytes +
                encrypted_data
            )
            
            encrypted_path = self.get_encrypted_path(db_name)
            with open(encrypted_path, "wb") as f:
                f.write(output_data)
            
            self.crypto.save_config(db_name, {
                "encrypted_path": encrypted_path,
                "original_size": original_size,
                "description": description
            })
            
            return True, f"加密成功！\n原始大小: {original_size:,} 字节\n加密后大小: {len(output_data):,} 字节"
        
        except Exception as e:
            return False, f"加密失败: {str(e)}"
    
    def decrypt_database(
        self,
        db_name: str,
        output_path: str,
        verify_checksum: bool = True
    ) -> Tuple[bool, str]:
        try:
            encrypted_path = self.get_encrypted_path(db_name)
            
            if not os.path.exists(encrypted_path):
                return False, f"加密文件不存在: {encrypted_path}"
            
            with open(encrypted_path, "rb") as f:
                file_data = f.read()
            
            offset = 0
            
            magic = file_data[offset:offset + len(self.MAGIC_HEADER)]
            if magic != self.MAGIC_HEADER:
                return False, "无效的加密文件格式"
            offset += len(self.MAGIC_HEADER)
            
            meta_length = struct.unpack('>I', file_data[offset:offset + 4])[0]
            offset += 4
            
            meta_bytes = file_data[offset:offset + meta_length]
            metadata = json.loads(meta_bytes.decode('utf-8'))
            offset += meta_length
            
            encrypted_data = file_data[offset:]
            
            decrypted_data = self.crypto.decrypt_data(encrypted_data)
            
            if verify_checksum:
                checksum = self._calculate_checksum(decrypted_data)
                if checksum != metadata.get("original_checksum"):
                    return False, "校验和验证失败，数据可能被篡改！"
            
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            
            return True, f"解密成功！\n文件已保存到: {output_path}\n原始大小: {metadata['original_size']:,} 字节"
        
        except CryptoError as e:
            return False, f"解密失败（密码错误）: {str(e)}"
        except Exception as e:
            return False, f"解密失败: {str(e)}"
    
    def list_encrypted_databases(self) -> list:
        databases = []
        
        if not os.path.exists(self.get_encrypted_path("")):
            return databases
        
        config_names = self.crypto.list_databases()
        
        encrypted_path = self.get_encrypted_path("")
        if os.path.exists(encrypted_path):
            db_dir = os.path.dirname(encrypted_path)
            for f in os.listdir(db_dir):
                if f.endswith('.enc'):
                    db_name = f[:-4]
                    if db_name in config_names:
                        databases.append(db_name)
        
        return databases
    
    def get_database_info(self, db_name: str) -> Optional[dict]:
        encrypted_path = self.get_encrypted_path(db_name)
        
        if not os.path.exists(encrypted_path):
            return None
        
        try:
            with open(encrypted_path, "rb") as f:
                file_data = f.read()
            
            offset = len(self.MAGIC_HEADER)
            meta_length = struct.unpack('>I', file_data[offset:offset + 4])[0]
            offset += 4
            meta_bytes = file_data[offset:offset + meta_length]
            metadata = json.loads(meta_bytes.decode('utf-8'))
            
            return metadata
        except Exception:
            return None
    
    def delete_database(self, db_name: str) -> Tuple[bool, str]:
        try:
            encrypted_path = self.get_encrypted_path(db_name)
            
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
                return True, f"已删除加密文件: {db_name}"
            else:
                return False, f"文件不存在: {db_name}"
        
        except Exception as e:
            return False, f"删除失败: {str(e)}"