import json
import os
import base64
from typing import Any, Dict, Optional, cast
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
SALT_SIZE = 32          
NONCE_SIZE = 12         
KEY_SIZE = 32           
PBKDF2_ITERATIONS = 600_000  
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))
def encrypt_results(data: Dict[str, Any], password: str) -> bytes:
    plaintext = json.dumps(data, indent=2, default=str).encode("utf-8")
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return salt + nonce + ciphertext
def decrypt_results(blob: bytes, password: str) -> Dict[str, Any]:
    blob_any = cast(Any, blob)
    salt = blob_any[:SALT_SIZE]
    nonce = blob_any[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob_any[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(plaintext.decode("utf-8"))
def save_encrypted(
    data: Dict[str, Any],
    password: str,
    filepath: str,
) -> str:
    blob = encrypt_results(data, password)
    with open(filepath, "wb") as f:
        f.write(base64.b64encode(blob))
    return os.path.abspath(filepath)
def load_encrypted(
    filepath: str,
    password: str,
) -> Dict[str, Any]:
    with open(filepath, "rb") as f:
        blob = base64.b64decode(f.read())
    return decrypt_results(blob, password)

class Encryptor:
    def __init__(self, password: str):
        self.password = password

    def save(self, data: Dict[str, Any], filepath: str) -> str:
        return save_encrypted(data, self.password, filepath)

    def load(self, filepath: str) -> Dict[str, Any]:
        return load_encrypted(filepath, self.password)