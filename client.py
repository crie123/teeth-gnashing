import aiohttp
import asyncio
import os
import time
import hashlib
import random
from math import gcd
import hmac
import base64
import json
from typing import Optional, Dict, List, Tuple, Union
from dataclasses import dataclass
from pathlib import Path

@dataclass
class CryptoConfig:
    server_url: str
    secret_key: bytes
    max_drift: int = 60
    handshake_points: int = 8
    hash_size: int = 16

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
        """
        Initialize the crypto client with configuration
        Args:
            config: Can be a CryptoConfig object, path to json config file, or dict with config values
        """
        self._config = self._load_config(config)
        self._session: Optional[aiohttp.ClientSession] = None
        self._points: Optional[List[Tuple[float, float, float, float]]] = None

    @staticmethod
    def _load_config(config: Optional[Union[CryptoConfig, str, dict]] = None) -> CryptoConfig:
        if isinstance(config, CryptoConfig):
            return config
        
        if config is None:
            config = {}
        elif isinstance(config, str):
            # Load from JSON file
            try:
                with open(config, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                raise CryptoError(f"Failed to load config from file: {e}")

        # Default values
        return CryptoConfig(
            server_url=config.get('server_url', "http://localhost:8000"),
            secret_key=base64.b64decode(config.get('secret_key', 'c3VwZXJfc2VjcmV0X2tleV9mb3JfaG1hYw==')),
            max_drift=config.get('max_drift', 60),
            handshake_points=config.get('handshake_points', 8),
            hash_size=config.get('hash_size', 16)
        )

    def _generate_function_points(self) -> List[Tuple[float, float, float, float]]:
        """Generate random points for handshake"""
        return [(
            random.uniform(-1, 1),
            random.uniform(-1, 1),
            random.uniform(-1, 1),
            random.uniform(0, 1)
        ) for _ in range(self._config.handshake_points)]

    def _hash_function_points(self, points: List[Tuple[float, float, float, float]]) -> bytes:
        """Hash the function points for handshake"""
        flat = b"".join([
            float(x).hex().encode() + float(y).hex().encode() + 
            float(z).hex().encode() + float(v).hex().encode()
            for x, y, z, v in points
        ])
        return hashlib.blake2s(flat, digest_size=self._config.hash_size).digest()

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
        """Derive encryption key from snapshot and salt"""
        seed = snapshot['seed']
        tick = snapshot['tick'] ^ int.from_bytes(salt[:4], 'little')

        arr = [[[0 for _ in range(4)] for _ in range(4)] for _ in range(4)]
        value = seed
        for i in range(64):
            z, y, x = i // 16, (i % 16) // 4, i % 4
            arr[z][y][x] = value
            value += 1 if z < 2 else -1

        tick_bytes = []
        for i in range(64):
            z, y, x = i // 16, (i % 16) // 4, i % 4
            tick_val = arr[z][y][x]
            pos_val = ((z << 4) | (y << 2) | x) & 0xFF
            tick_b = (pos_val ^ (tick_val & 0xFF) ^ salt[i % len(salt)]) & 0xFF or 1
            
            attempts = 0
            while gcd(tick_b, 256) != 1:
                tick_b = (tick_b + 1) % 256 or 1
                attempts += 1
                if attempts > 256:
                    raise CryptoError("Failed to generate invertible tick byte")
                    
            tick_bytes.append(tick_b)

        return tick_bytes

    @staticmethod
    def encrypt_stream(byte_stream: Union[bytes, bytearray], tick_key: List[int], salt: bytes) -> bytearray:
        """Encrypt a byte stream using the derived key"""
        result = bytearray(salt)
        for i, b in enumerate(byte_stream):
            t = tick_key[i % 64]
            result.append((b * t) % 256)
        return result

    @staticmethod
    def decrypt_stream(encrypted_stream: Union[bytes, bytearray], tick_key: List[int]) -> bytearray:
        """Decrypt a byte stream using the derived key"""
        result = bytearray()
        for i, b in enumerate(encrypted_stream):
            t = tick_key[i % 64]
            t_inv = pow(t, -1, 256)
            result.append((b * t_inv) % 256)
        return result

    @staticmethod
    def fast_hash(data: Union[bytes, bytearray], digest_size: int = 16) -> bytes:
        """Generate a fast hash of data"""
        return hashlib.blake2s(data, digest_size=digest_size).digest()

    async def encrypt_message(self, message: Union[str, bytes]) -> bytes:
        """
        Encrypt a message using the current snapshot
        Args:
            message: The message to encrypt (string or bytes)
        Returns:
            bytes: The encrypted message with hash and salt
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        snapshot = await self.get_snapshot()
        salt = int(time.time()).to_bytes(8, 'little') + os.urandom(8)
        tick_key = self.derive_key_from_snapshot(snapshot, salt)

        encrypted = self.encrypt_stream(message, tick_key, salt)
        hashed = self.fast_hash(encrypted)
        return hashed + encrypted

    async def decrypt_message(self, encrypted: bytes) -> bytes:
        """
        Decrypt an encrypted message
        Args:
            encrypted: The encrypted message (with hash and salt)
        Returns:
            bytes: The decrypted message
        """
        if len(encrypted) < 32:
            raise ValueError("Encrypted data too short")

        snapshot = await self.get_snapshot()
        recv_hash = encrypted[:16]
        salt = encrypted[16:32]
        payload = encrypted[32:]

        tick_key = self.derive_key_from_snapshot(snapshot, salt)
        decrypted = self.decrypt_stream(payload, tick_key)

        actual_hash = self.fast_hash(encrypted[16:])
        if recv_hash != actual_hash:
            raise CryptoError("Hash mismatch! Possible tampering or corruption.")

        return bytes(decrypted)

async def main():
    """Example usage of the CryptoClient"""
    config = CryptoConfig(
        server_url="http://localhost:8000",
        secret_key=b"super_secret_key_for_hmac",
        max_drift=60
    )

    async with CryptoClient(config) as client:
        await client.authenticate()
        
        # Example with string
        message = "это пример шифрования с динамическим tick, хэшем и handshake-функцией"
        encrypted = await client.encrypt_message(message)
        decrypted = await client.decrypt_message(encrypted)
        print("Decrypted text:", decrypted.decode('utf-8'))
        
        # Example with bytes
        binary_data = os.urandom(1024)  # 1KB of random data
        encrypted = await client.encrypt_message(binary_data)
        decrypted = await client.decrypt_message(encrypted)
        print("Binary data matches:", binary_data == decrypted)

if __name__ == "__main__":
    asyncio.run(main())
