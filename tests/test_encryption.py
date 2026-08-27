import pytest
import os
import tempfile
from ops.encryption import (
    encrypt_results,
    decrypt_results,
    save_encrypted,
    load_encrypted,
    derive_key,
    SALT_SIZE,
    NONCE_SIZE,
    KEY_SIZE,
)
from cryptography.exceptions import InvalidTag
class TestKeyDerivation:
    def test_key_length(self):
        salt = os.urandom(SALT_SIZE)
        key = derive_key("test_password", salt)
        assert len(key) == KEY_SIZE
    def test_same_password_same_salt(self):
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key("password", salt)
        key2 = derive_key("password", salt)
        assert key1 == key2
    def test_different_salt_different_key(self):
        key1 = derive_key("password", os.urandom(SALT_SIZE))
        key2 = derive_key("password", os.urandom(SALT_SIZE))
        assert key1 != key2
    def test_different_password_different_key(self):
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2
class TestEncryptDecrypt:
    def test_round_trip(self):
        data = {"port": 80, "state": "open", "banner": "nginx/1.24"}
        password = "test_secret_password"
        encrypted = encrypt_results(data, password)
        decrypted = decrypt_results(encrypted, password)
        assert decrypted == data
    def test_wrong_password_fails(self):
        data = {"port": 443, "state": "open"}
        encrypted = encrypt_results(data, "correct_password")
        with pytest.raises(InvalidTag):
            decrypt_results(encrypted, "wrong_password")
    def test_tampered_data_fails(self):
        data = {"port": 22, "state": "open"}
        encrypted = encrypt_results(data, "password")
        tampered = bytearray(encrypted)
        tampered[-5] ^= 0xFF
        tampered = bytes(tampered)
        with pytest.raises(InvalidTag):
            decrypt_results(tampered, "password")
    def test_output_format(self):
        data = {"test": True}
        encrypted = encrypt_results(data, "pass")
        assert len(encrypted) >= SALT_SIZE + NONCE_SIZE + 16
    def test_unique_encryption(self):
        data = {"test": True}
        enc1 = encrypt_results(data, "pass")
        enc2 = encrypt_results(data, "pass")
        assert enc1 != enc2
    def test_complex_data(self):
        data = {
            "target": "192.168.1.1",
            "ports_scanned": 1024,
            "open_ports": [
                {"port": 22, "service": "ssh", "banner": "OpenSSH_8.9"},
                {"port": 80, "service": "http", "banner": "nginx"},
                {"port": 443, "service": "https", "tls": "TLSv1.3"},
            ],
            "heat_level": 0.15,
            "elapsed": 3600.5,
            "nested": {"deep": {"data": [1, 2, 3]}},
        }
        password = "complex_test_password!"
        encrypted = encrypt_results(data, password)
        decrypted = decrypt_results(encrypted, password)
        assert decrypted == data
        assert decrypted["open_ports"][0]["banner"] == "OpenSSH_8.9"
class TestFileSaveLoad:
    def test_save_and_load(self):
        data = {"scanner": "usare", "version": "1.0"}
        password = "file_test_pass"
        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as f:
            filepath = f.name
        try:
            save_encrypted(data, password, filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
            loaded = load_encrypted(filepath, password)
            assert loaded == data
        finally:
            os.unlink(filepath)
    def test_load_wrong_password(self):
        data = {"secret": "data"}
        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as f:
            filepath = f.name
        try:
            save_encrypted(data, "correct", filepath)
            with pytest.raises(InvalidTag):
                load_encrypted(filepath, "incorrect")
        finally:
            os.unlink(filepath)