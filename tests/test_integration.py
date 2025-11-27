import pytest
import asyncio
import base64
from client import CryptoClient, CryptoConfig
from server import ServerConfig, ServerState
import hashlib
import hmac


class TestIntegrationEncryptionDecryption:
    """Integration tests for encryption and decryption"""

    def test_full_encrypt_decrypt_flow(self):
        """Test complete encryption and decryption flow"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"super_secret_key_for_hmac",
            array_size=256
        ))
        
        # Simulate a snapshot
        snapshot = {
            "tick": 42,
            "seed": 54321,
            "timestamp": 1234567890,
            "signature": "dummy"
        }
        
        message = b"This is a secret message"
        salt = b"0" * 32  # 32 bytes salt
        
        # Derive key
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        
        # Encrypt
        encrypted = client.encrypt_stream(message, tick_key, salt)
        
        # Decrypt
        decrypted = client.decrypt_stream(encrypted, tick_key)
        
        assert bytes(decrypted) == message

    def test_encrypt_decrypt_various_sizes(self):
        """Test encryption/decryption with various data sizes"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 1, "seed": 100, "timestamp": 123456, "signature": "x"}
        salt = b"a" * 32
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        
        test_sizes = [1, 10, 100, 255, 256, 1000]
        
        for size in test_sizes:
            message = bytes(range(256)) * (size // 256 + 1)
            message = message[:size]
            
            encrypted = client.encrypt_stream(message, tick_key, salt)
            decrypted = client.decrypt_stream(encrypted, tick_key)
            
            assert bytes(decrypted) == message, f"Failed for size {size}"

    def test_encrypt_decrypt_binary_data(self):
        """Test encryption/decryption with binary data"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 5, "seed": 200, "timestamp": 123456, "signature": "x"}
        salt = b"b" * 32
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        
        # Binary data with all byte values
        binary_data = bytes(range(256)) + bytes(reversed(range(256)))
        
        encrypted = client.encrypt_stream(binary_data, tick_key, salt)
        decrypted = client.decrypt_stream(encrypted, tick_key)
        
        assert bytes(decrypted) == binary_data


class TestIntegrationServerClient:
    """Integration tests between server and client components"""

    def test_snapshot_signature_verification_flow(self):
        """Test the complete snapshot signature verification flow"""
        # Server side
        server_secret = b"super_secret_key_for_hmac"
        tick, seed, timestamp = 100, 54321, 1234567890
        
        msg = f"{tick}|{seed}|{timestamp}".encode()
        server_sig = hmac.new(server_secret, msg, hashlib.sha256).digest()
        server_sig_b64 = base64.b64encode(server_sig).decode()
        
        # Client side
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=server_secret
        ))
        
        # Client verifies
        is_valid = client.verify_snapshot_signature(tick, seed, timestamp, server_sig_b64)
        assert is_valid is True

    def test_key_derivation_consistency(self):
        """Test that key derivation is consistent across client instances"""
        secret = b"shared_secret"
        snapshot = {
            "tick": 123,
            "seed": 456,
            "timestamp": 789,
            "signature": "sig"
        }
        salt = b"consistent_salt_" * 2
        
        # Create two clients
        client1 = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=secret,
            array_size=256
        ))
        
        client2 = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=secret,
            array_size=256
        ))
        
        # Derive keys
        key1 = client1.derive_key_from_snapshot(snapshot, salt)
        key2 = client2.derive_key_from_snapshot(snapshot, salt)
        
        # Should be identical
        assert key1 == key2

    def test_different_salts_produce_different_keys(self):
        """Test that different salts produce different derived keys"""
        snapshot = {
            "tick": 123,
            "seed": 456,
            "timestamp": 789,
            "signature": "sig"
        }
        secret = b"shared_secret"
        
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=secret,
            array_size=256
        ))
        
        key1 = client.derive_key_from_snapshot(snapshot, b"salt1" + b"0" * 27)
        key2 = client.derive_key_from_snapshot(snapshot, b"salt2" + b"0" * 27)
        
        # Should be different
        assert key1 != key2


class TestIntegrationConfigLoading:
    """Integration tests for configuration loading"""

    def test_client_config_from_dict(self):
        """Test client configuration loading from dictionary"""
        config_dict = {
            "server_url": "http://localhost:8000",
            "secret_key": base64.b64encode(b"test_key").decode(),
            "max_drift": 120,
            "handshake_points": 16,
            "hash_size": 64,
            "array_size": 512
        }
        
        client = CryptoClient(config_dict)
        
        assert client._config.server_url == "http://localhost:8000"
        assert client._config.max_drift == 120
        assert client._config.handshake_points == 16

    def test_server_config_with_client_config(self):
        """Test that server and client can use same secret"""
        secret = b"shared_encryption_secret"
        
        server_config = ServerConfig(
            secret_key=base64.b64encode(secret).decode(),
            tick_interval=1.0,
            host="localhost",
            port=8000
        )
        
        client_config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=secret
        )
        
        # Both should have the same secret key
        assert base64.b64decode(server_config.secret_key) == client_config.secret_key


class TestIntegrationDataIntegrity:
    """Integration tests for data integrity"""

    def test_tampered_data_detected_via_hash(self):
        """Test that tampered encrypted data is detected via hash"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 1, "seed": 100, "timestamp": 123456, "signature": "x"}
        message = b"Important data"
        salt = b"x" * 32
        
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        encrypted = client.encrypt_stream(message, tick_key, salt)
        
        # Calculate hash
        hash_input = salt + encrypted + snapshot['tick'].to_bytes(8, 'little')
        correct_hash = client.fast_hash(hash_input, 32)
        
        # Tamper with data
        tampered = bytearray(encrypted)
        tampered[0] ^= 0xFF  # Flip bits in first byte
        
        # Calculate hash of tampered data
        tampered_hash_input = salt + tampered + snapshot['tick'].to_bytes(8, 'little')
        tampered_hash = client.fast_hash(tampered_hash_input, 32)
        
        # Hashes should be different
        assert correct_hash != tampered_hash

    def test_message_decryption_verification(self):
        """Test that correct hash matches computed hash"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 10, "seed": 200, "timestamp": 123456, "signature": "x"}
        message = b"Test message"
        salt = b"y" * 32
        
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        encrypted = client.encrypt_stream(message, tick_key, salt)
        
        # Original hash
        hash_input = salt + encrypted + snapshot['tick'].to_bytes(8, 'little')
        original_hash = client.fast_hash(hash_input, 32)
        
        # Recompute hash
        recomputed_hash_input = salt + encrypted + snapshot['tick'].to_bytes(8, 'little')
        recomputed_hash = client.fast_hash(recomputed_hash_input, 32)
        
        # Should match
        assert original_hash == recomputed_hash


class TestIntegrationEdgeCases:
    """Integration tests for edge cases"""

    def test_encrypt_empty_message(self):
        """Test encryption of empty message"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 1, "seed": 100, "timestamp": 123456, "signature": "x"}
        salt = b"z" * 32
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        
        message = b""
        encrypted = client.encrypt_stream(message, tick_key, salt)
        decrypted = client.decrypt_stream(encrypted, tick_key)
        
        assert bytes(decrypted) == message

    def test_encrypt_single_byte(self):
        """Test encryption of single byte"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 1, "seed": 100, "timestamp": 123456, "signature": "x"}
        salt = b"w" * 32
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        
        message = b"\xFF"
        encrypted = client.encrypt_stream(message, tick_key, salt)
        decrypted = client.decrypt_stream(encrypted, tick_key)
        
        assert bytes(decrypted) == message

    def test_large_message_encryption(self):
        """Test encryption of large message"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {"tick": 1, "seed": 100, "timestamp": 123456, "signature": "x"}
        salt = b"v" * 32
        tick_key = client.derive_key_from_snapshot(snapshot, salt)
        
        # Create a 10KB message
        message = b"x" * 10240
        encrypted = client.encrypt_stream(message, tick_key, salt)
        decrypted = client.decrypt_stream(encrypted, tick_key)
        
        assert bytes(decrypted) == message
        assert len(encrypted) == len(message)

    def test_multiple_snapshots_different_keys(self):
        """Test that different snapshots produce different keys"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        salt = b"test_salt" + b"0" * 23
        
        snapshot1 = {"tick": 1, "seed": 100, "timestamp": 123456, "signature": "x"}
        snapshot2 = {"tick": 2, "seed": 100, "timestamp": 123456, "signature": "x"}
        snapshot3 = {"tick": 1, "seed": 101, "timestamp": 123456, "signature": "x"}
        
        key1 = client.derive_key_from_snapshot(snapshot1, salt)
        key2 = client.derive_key_from_snapshot(snapshot2, salt)
        key3 = client.derive_key_from_snapshot(snapshot3, salt)
        
        # All should be different
        assert key1 != key2
        assert key1 != key3
        assert key2 != key3
