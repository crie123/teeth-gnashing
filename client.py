import aiohttp
import asyncio
import os
import time
import hashlib
import random
import hmac
import base64
import json
from typing import Optional, Dict, List, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import secrets
from math import gcd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

@dataclass
class CryptoConfig:
    server_url: str
    secret_key: bytes
    max_drift: int = 60
    handshake_points: int = 8
    hash_size: int = 32  # Increased hash size
    array_size: int = 256  # Base array size (must be multiple of 64)

class CryptoError(Exception):
    """Base exception for array-crypto library"""
    pass

class AuthenticationError(CryptoError):
    """Raised when authentication with the server fails"""
    pass

class SnapshotError(CryptoError):
    """Raised when there are issues with snapshot verification"""
    pass

class CryptoClient:
    def __init__(self, config: Optional[Union[CryptoConfig, str, dict]] = None):
        """Initialize the crypto client with configuration"""
        self._config = self._load_config(config)
        if self._config.array_size % 64 != 0:
            raise CryptoError("Array size must be multiple of 64")
        self._session: Optional[aiohttp.ClientSession] = None
        self._points: Optional[List[Tuple[float, float, float, float]]] = None

    @staticmethod
    def _load_config(config: Optional[Union[CryptoConfig, str, dict]] = None) -> CryptoConfig:
        if isinstance(config, CryptoConfig):
            return config
        
        if config is None:
            config = {}
        elif isinstance(config, str):
            try:
                with open(config, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                raise CryptoError(f"Failed to load config: {e}")

        # Handle string secret key conversion
        secret_key = config.get('secret_key', 'c3VwZXJfc2VjcmV0X2tleV9mb3JfaG1hYw==')
        if isinstance(secret_key, str):
            secret_key = base64.b64decode(secret_key)

        return CryptoConfig(
            server_url=config.get('server_url', "http://localhost:8000"),
            secret_key=secret_key,
            max_drift=config.get('max_drift', 60),
            handshake_points=config.get('handshake_points', 8),
            hash_size=config.get('hash_size', 32),
            array_size=config.get('array_size', 256)
        )

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    async def close(self):
        """Close the client session"""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        """Context manager entry"""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.close()

    def _generate_function_points(self) -> List[Tuple[float, float, float, float]]:
        """Generate random points for handshake with improved entropy"""
        return [(
            random.uniform(-1e6, 1e6),  # Increased range
            random.uniform(-1e6, 1e6),
            random.uniform(-1e6, 1e6),
            random.uniform(0, 1e6)
        ) for _ in range(self._config.handshake_points)]

    def _hash_function_points(self, points: List[Tuple[float, float, float, float]]) -> bytes:
        """Hash the function points for handshake"""
        flat = b"".join([
            float(x).hex().encode() + float(y).hex().encode() + 
            float(z).hex().encode() + float(v).hex().encode()
            for x, y, z, v in points
        ])
        return hashlib.blake2b(flat, digest_size=self._config.hash_size).digest()

    def verify_snapshot_signature(self, tick: int, seed: int, timestamp: int, signature: str) -> bool:
        """Verify the HMAC signature of a snapshot"""
        msg = f"{tick}|{seed}|{timestamp}".encode()
        expected = hmac.new(self._config.secret_key, msg, hashlib.sha256).digest()
        return base64.b64encode(expected).decode() == signature

    async def authenticate(self) -> None:
        """Perform handshake authentication with the server"""
        await self._ensure_session()
        self._points = self._generate_function_points()
        func_hash = self._hash_function_points(self._points)
        payload = {"hash": func_hash.hex()}
        
        try:
            async with self._session.post(f"{self._config.server_url}/handshake", json=payload) as resp:
                if resp.status != 200:
                    raise AuthenticationError(f"Authentication failed with status {resp.status}")
                data = await resp.json()
                if data.get('status') != 'ok':
                    raise AuthenticationError(f"Server rejected handshake: {data.get('status')}")
        except Exception as e:
            raise AuthenticationError(f"Authentication failed: {str(e)}")

    async def get_snapshot(self) -> Dict[str, Union[int, str]]:
        """Get and verify a snapshot from the server"""
        await self._ensure_session()
        try:
            async with self._session.get(f"{self._config.server_url}/snapshot") as response:
                if response.status != 200:
                    raise SnapshotError(f"Failed to get snapshot: HTTP {response.status}")
                
                snap = await response.json()
                now = int(time.time())
                
                if abs(now - snap["timestamp"]) > self._config.max_drift:
                    raise SnapshotError("Snapshot expired or too far in future")
                
                if not self.verify_snapshot_signature(
                    snap["tick"], snap["seed"], snap["timestamp"], snap["signature"]
                ):
                    raise SnapshotError("Invalid snapshot signature")
                
                return snap
        except Exception as e:
            raise SnapshotError(f"Failed to get snapshot: {str(e)}")

    def derive_key_from_snapshot(self, snapshot: Dict[str, Union[int, str]], salt: bytes) -> List[int]:
        """Generate encryption key from snapshot and salt with improved complexity"""
        seed = snapshot['seed']
        tick = snapshot['tick']
        
        # Generate 32-byte key for ChaCha20 (256 bits)
        initial_entropy = hashlib.blake2b(
            seed.to_bytes(8, 'little') + 
            tick.to_bytes(8, 'little') + 
            salt,
            digest_size=32
        ).digest()
        
        # Use ChaCha20 for better entropy
        chacha_key = initial_entropy  # 32 bytes key
        nonce = hashlib.blake2b(salt, digest_size=16).digest()  # 16 bytes nonce
        
        chacha = Cipher(
            algorithms.ChaCha20(chacha_key, nonce),
            mode=None,
            backend=default_backend()
        ).encryptor()
        
        array_size = self._config.array_size
        dim_size = 8
        z_dim = 4
        
        # Generate random data
        random_data = chacha.update(bytes(array_size))
        
        # Create 3D array with improved entropy
        arr = [[[0 for _ in range(dim_size)] for _ in range(dim_size)] for _ in range(z_dim)]
        
        for i in range(array_size):
            z = (i // (dim_size * dim_size)) % z_dim
            y = (i // dim_size) % dim_size
            x = i % dim_size
            arr[z][y][x] = random_data[i]
        
        # Generate tick bytes with guaranteed invertibility
        tick_bytes = []
        salt_len = len(salt)
        
        # Use HMAC for additional entropy
        hmac_key = hashlib.blake2b(initial_entropy, digest_size=32).digest()
        h = hmac.new(hmac_key, digestmod=hashlib.blake2b)
        
        for i in range(array_size):
            z = (i // (dim_size * dim_size)) % z_dim
            y = (i // dim_size) % dim_size
            x = i % dim_size
            
            # Add entropy from multiple sources
            h.update(bytes([arr[z][y][x]]))
            h.update(salt[i % salt_len:i % salt_len + 1])
            h.update(i.to_bytes(4, 'little'))
            
            digest = h.digest()
            base = int.from_bytes(digest[:4], 'little')
            
            # Ensure coprime with 256 through odd numbers
            base = (base % 127) * 2 + 1  # Odd number 1-255
            
            if base == 0 or gcd(base, 256) != 1:
                base = 1
                
            tick_bytes.append(base)
            
        return tick_bytes

    @staticmethod
    def encrypt_stream(byte_stream: Union[bytes, bytearray], tick_key: List[int], salt: bytes) -> bytearray:
        """Basic reliable encryption with minimal operations"""
        result = bytearray()
        key_length = len(tick_key)
        
        for i, b in enumerate(byte_stream):
            t = tick_key[i % key_length]
            encrypted = (b * t) % 256
            result.append(encrypted)
        
        return result

    @staticmethod
    def decrypt_stream(encrypted_stream: Union[bytes, bytearray], tick_key: List[int]) -> bytearray:
        """Basic reliable decryption"""
        result = bytearray()
        
        for i, b in enumerate(encrypted_stream):
            t = tick_key[i % len(tick_key)]
            decrypted = (b * pow(t, -1, 256)) % 256
            result.append(decrypted)
        
        return result

    @staticmethod
    def fast_hash(data: Union[bytes, bytearray], digest_size: int = 32) -> bytes:
        """Enhanced hashing with improved entropy mixing"""
        h1 = hashlib.blake2b(data, digest_size=digest_size, key=b"round1").digest()
        h2 = hashlib.blake2b(h1 + data, digest_size=digest_size, key=b"round2").digest()
        h3 = hashlib.blake2b(h2 + data, digest_size=digest_size, key=b"round3").digest()
        
        result = bytearray(digest_size)
        for i in range(digest_size):
            result[i] = h1[i] ^ h2[i] ^ h3[i]
        
        return bytes(result)

    async def encrypt_message(self, message: Union[str, bytes]) -> bytes:
        """Encrypt a message with proper salt handling"""
        if isinstance(message, str):
            message = message.encode('utf-8')

        snapshot = await self.get_snapshot()
        
        # Generate salt with multiple entropy sources
        timestamp_bytes = int(time.time() * 1000).to_bytes(8, 'little')
        random_bytes = secrets.token_bytes(32)
        process_entropy = os.urandom(16)
        salt_input = timestamp_bytes + random_bytes + process_entropy
        salt = hashlib.blake2b(salt_input, digest_size=32).digest()
        
        tick_key = self.derive_key_from_snapshot(snapshot, salt)
        encrypted = self.encrypt_stream(message, tick_key, salt)
        
        # Calculate hash
        hash_input = salt + encrypted + snapshot['tick'].to_bytes(8, 'little')
        hashed = self.fast_hash(hash_input, self._config.hash_size)
        
        return hashed + salt + encrypted

    async def decrypt_message(self, encrypted: bytes) -> bytes:
        """Decrypt a message with proper salt handling"""
        if len(encrypted) < 64:
            raise ValueError("Encrypted data too short")

        snapshot = await self.get_snapshot()
        hash_size = self._config.hash_size
        
        recv_hash = encrypted[:hash_size]
        salt = encrypted[hash_size:hash_size*2]
        encrypted_data = encrypted[hash_size*2:]
        
        hash_input = salt + encrypted_data + snapshot['tick'].to_bytes(8, 'little')
        actual_hash = self.fast_hash(hash_input, self._config.hash_size)
        
        if recv_hash != actual_hash:
            raise CryptoError("Hash mismatch! Possible tampering or corruption.")

        tick_key = self.derive_key_from_snapshot(snapshot, salt)
        return bytes(self.decrypt_stream(encrypted_data, tick_key))

async def main():
    """Test the encryption/decryption functionality"""
    config = CryptoConfig(
        server_url="http://localhost:8000",
        secret_key=b"super_secret_key_for_hmac",
        max_drift=60
    )

    async with CryptoClient(config) as client:
        await client.authenticate()
        message = "Hello, world!"
        encrypted = await client.encrypt_message(message)
        decrypted = await client.decrypt_message(encrypted)
        print(f"Original: {message}")
        print(f"Decrypted: {decrypted.decode('utf-8')}")
        print(f"Match: {message.encode() == decrypted}")

if __name__ == "__main__":
    asyncio.run(main())
