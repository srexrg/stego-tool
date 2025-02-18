from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class CryptoError(Exception):
    pass

def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    except Exception as e:
        raise CryptoError(f"Key derivation failed: {str(e)}")

def encrypt_data(password: str, data: bytes) -> bytes:
    """
    Encrypt data using AES-256-CBC with proper key derivation.
    Returns concatenated salt + iv + ciphertext.
    """
    try:
        if not password or not data:
            raise ValueError("Password and data must not be empty")
        
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return salt + iv + ciphertext
    except Exception as e:
        raise CryptoError(f"Encryption failed: {str(e)}")

def decrypt_data(password: str, encrypted_data: bytes) -> bytes:
    """
    Decrypt data using AES-256-CBC.
    Expects input in format: salt + iv + ciphertext
    """
    try:
        if len(encrypted_data) < 32:
            raise ValueError("Invalid encrypted data format")
            
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_padded) + unpadder.finalize()
    except Exception as e:
        raise CryptoError(f"Decryption failed: {str(e)}")