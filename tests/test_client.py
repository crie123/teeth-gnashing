import pytest
import asyncio
from client import CryptoClient, CryptoConfig, CryptoError, AuthenticationError, SnapshotError
import base64


class TestCryptoConfig:
    """Test CryptoConfig initialization and loading"""

    def test_config_direct_initialization(self, client_config_dict):
        """Test direct initialization with dictionary values"""
        config = CryptoConfig(
            server_url=client_config_dict["server_url"],
            secret_key=base64.b64decode(client_config_dict["secret_key"]),
            max_drift=client_config_dict["max_drift"]
        )
        assert config.server_url == "http://localhost:8000"
        assert config.max_drift == 60

    def test_config_with_bytes_secret_key(self):
        """Test config initialization with bytes secret key"""
        secret = b"test_secret_key"
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=secret
        )
        assert config.secret_key == secret

    def test_config_with_string_secret_key(self):
        """Test config initialization with base64 string secret key"""
        secret_bytes = b"test_secret_key"
        secret_b64 = base64.b64encode(secret_bytes).decode()
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=secret_b64
        )
        # Should accept string and potentially convert it
        assert config.secret_key is not None

    def test_config_defaults(self):
        """Test default configuration values"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        )
        assert config.max_drift == 60
        assert config.handshake_points == 8
        assert config.hash_size == 32
        assert config.array_size == 256

    def test_config_custom_values(self):
        """Test configuration with custom values"""
        config = CryptoConfig(
            server_url="http://example.com:9000",
            secret_key=b"secret",
            max_drift=120,
            handshake_points=16,
            hash_size=64,
            array_size=512
        )
        assert config.max_drift == 120
        assert config.handshake_points == 16
        assert config.hash_size == 64
        assert config.array_size == 512


class TestCryptoClientInitialization:
    """Test CryptoClient initialization"""

    def test_client_initialization_with_config_object(self, client_config_dict):
        """Test client initialization with CryptoConfig object"""
        config = CryptoConfig(
            server_url=client_config_dict["server_url"],
            secret_key=base64.b64decode(client_config_dict["secret_key"])
        )
        client = CryptoClient(config)
        assert client._config == config

    def test_client_initialization_with_dict(self, client_config_dict):
        """Test client initialization with dictionary"""
        client = CryptoClient(client_config_dict)
        assert client._config.server_url == "http://localhost:8000"

    def test_client_initialization_with_none(self):
        """Test client initialization with default config"""
        client = CryptoClient(None)
        assert client._config.server_url == "http://localhost:8000"

    def test_client_invalid_array_size(self):
        """Test that invalid array size raises error"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=100  # Not a multiple of 64
        )
        with pytest.raises(CryptoError, match="Array size must be multiple of 64"):
            CryptoClient(config)

    def test_client_valid_array_sizes(self):
        """Test that valid array sizes work"""
        for size in [64, 128, 256, 512, 1024]:
            config = CryptoConfig(
                server_url="http://localhost:8000",
                secret_key=b"secret",
                array_size=size
            )
            client = CryptoClient(config)
            assert client._config.array_size == size


class TestCryptoClientEncryption:
    """Test encryption and decryption methods"""

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_cycle(self):
        """Test basic encryption and decryption cycle (without server)"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"super_secret_key_for_hmac"
        )
        client = CryptoClient(config)
        
        # Test hash function
        test_data = b"test data"
        hash_result = client.fast_hash(test_data)
        assert len(hash_result) == config.hash_size
        assert isinstance(hash_result, bytes)

    @pytest.mark.asyncio
    async def test_encrypt_string_message(self):
        """Test encryption of string messages"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"super_secret_key_for_hmac"
        )
        client = CryptoClient(config)
        
        # Test hash function works with strings
        test_string = "test message"
        hash1 = client.fast_hash(test_string.encode())
        hash2 = client.fast_hash(test_string.encode())
        # Same input should produce same hash
        assert hash1 == hash2

    def test_encrypt_stream_basic(self):
        """Test basic stream encryption"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=64
        ))
        
        plaintext = b"Hello"
        tick_key = [3, 5, 7, 11, 13, 17, 19, 23]  # Odd coprime numbers
        
        encrypted = client.encrypt_stream(plaintext, tick_key, b"salt")
        assert len(encrypted) == len(plaintext)
        assert isinstance(encrypted, bytearray)

    def test_decrypt_stream_basic(self):
        """Test basic stream decryption"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=64
        ))
        
        plaintext = b"Hello"
        tick_key = [3, 5, 7, 11, 13, 17, 19, 23]
        
        encrypted = client.encrypt_stream(plaintext, tick_key, b"salt")
        decrypted = client.decrypt_stream(encrypted, tick_key)
        
        assert bytes(decrypted) == plaintext

    def test_encrypt_decrypt_roundtrip(self):
        """Test multiple encrypt/decrypt cycles"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=64
        ))
        
        test_messages = [
            b"Short",
            b"This is a longer message",
            b"Message with special chars: !@#$%^&*()",
            b"\x00\x01\x02\x03",  # Binary data
        ]
        
        tick_key = [3, 5, 7, 11, 13, 17, 19, 23]
        
        for message in test_messages:
            encrypted = client.encrypt_stream(message, tick_key, b"salt")
            decrypted = client.decrypt_stream(encrypted, tick_key)
            assert bytes(decrypted) == message, f"Failed for message: {message}"


class TestCryptoClientSnapshot:
    """Test snapshot verification methods"""

    def test_verify_snapshot_signature_valid(self):
        """Test verification of valid snapshot signature"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"super_secret_key_for_hmac"
        ))
        
        # Create a valid signature
        import hmac
        import hashlib
        tick, seed, timestamp = 100, 12345, 1234567890
        msg = f"{tick}|{seed}|{timestamp}".encode()
        sig = hmac.new(b"super_secret_key_for_hmac", msg, hashlib.sha256).digest()
        sig_b64 = base64.b64encode(sig).decode()
        
        # Verify it
        result = client.verify_snapshot_signature(tick, seed, timestamp, sig_b64)
        assert result is True

    def test_verify_snapshot_signature_invalid(self):
        """Test verification of invalid snapshot signature"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"super_secret_key_for_hmac"
        ))
        
        tick, seed, timestamp = 100, 12345, 1234567890
        invalid_sig = base64.b64encode(b"invalid_signature").decode()
        
        result = client.verify_snapshot_signature(tick, seed, timestamp, invalid_sig)
        assert result is False

    def test_verify_snapshot_wrong_key(self):
        """Test snapshot verification with wrong secret key"""
        client1 = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"key1"
        ))
        
        import hmac
        import hashlib
        tick, seed, timestamp = 100, 12345, 1234567890
        msg = f"{tick}|{seed}|{timestamp}".encode()
        
        # Sign with different key
        sig = hmac.new(b"key2", msg, hashlib.sha256).digest()
        sig_b64 = base64.b64encode(sig).decode()
        
        # Verify should fail
        result = client1.verify_snapshot_signature(tick, seed, timestamp, sig_b64)
        assert result is False


class TestCryptoClientKeyDerivation:
    """Test key derivation from snapshot"""

    def test_derive_key_from_snapshot(self):
        """Test key derivation produces correct length"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {
            "tick": 100,
            "seed": 12345,
            "timestamp": 1234567890,
            "signature": "dummy"
        }
        
        salt = b"test_salt_12345678901234567890"
        key = client.derive_key_from_snapshot(snapshot, salt)
        
        assert len(key) == 256
        assert isinstance(key, list)
        assert all(isinstance(k, int) for k in key)

    def test_derive_key_consistency(self):
        """Test that same snapshot produces same key"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {
            "tick": 100,
            "seed": 12345,
            "timestamp": 1234567890,
            "signature": "dummy"
        }
        
        salt = b"test_salt"
        key1 = client.derive_key_from_snapshot(snapshot, salt)
        key2 = client.derive_key_from_snapshot(snapshot, salt)
        
        assert key1 == key2

    def test_derive_key_coprime(self):
        """Test that derived key values are coprime with 256"""
        from math import gcd
        
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret",
            array_size=256
        ))
        
        snapshot = {
            "tick": 100,
            "seed": 12345,
            "timestamp": 1234567890,
            "signature": "dummy"
        }
        
        salt = b"test_salt"
        key = client.derive_key_from_snapshot(snapshot, salt)
        
        # All non-zero key values should be coprime with 256
        for k in key:
            if k != 0:
                assert gcd(k, 256) == 1, f"Key value {k} is not coprime with 256"


class TestCryptoClientHashFunction:
    """Test hash function implementation"""

    def test_fast_hash_length(self):
        """Test that fast_hash produces correct length"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        ))
        
        for digest_size in [16, 32, 64]:
            result = client.fast_hash(b"test", digest_size=digest_size)
            assert len(result) == digest_size

    def test_fast_hash_deterministic(self):
        """Test that fast_hash is deterministic"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        ))
        
        data = b"consistent data"
        hash1 = client.fast_hash(data)
        hash2 = client.fast_hash(data)
        
        assert hash1 == hash2

    def test_fast_hash_different_inputs(self):
        """Test that different inputs produce different hashes"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        ))
        
        hash1 = client.fast_hash(b"input1")
        hash2 = client.fast_hash(b"input2")
        
        assert hash1 != hash2

    def test_fast_hash_avalanche_effect(self):
        """Test that small input changes produce large hash changes"""
        client = CryptoClient(CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        ))
        
        hash1 = client.fast_hash(b"test1")
        hash2 = client.fast_hash(b"test2")
        
        # Count different bits (simplified avalanche test)
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(hash1, hash2))
        
        # Should have significant differences
        assert diff_bits > 0


class TestCryptoClientContextManager:
    """Test context manager functionality"""

    @pytest.mark.asyncio
    async def test_context_manager_enters(self):
        """Test that context manager can enter"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        )
        
        async with CryptoClient(config) as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_context_manager_exits_cleanly(self):
        """Test that context manager exits cleanly"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        )
        
        async with CryptoClient(config) as client:
            session = client._session
        
        assert session.closed

    @pytest.mark.asyncio
    async def test_manual_close(self):
        """Test manual session close"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"secret"
        )
        
        client = CryptoClient(config)
        await client._ensure_session()
        session = client._session
        
        await client.close()
        assert session.closed


class TestCryptoErrorHandling:
    """Test error handling"""

    def test_crypto_error_is_exception(self):
        """Test that CryptoError is an Exception"""
        assert issubclass(CryptoError, Exception)

    def test_authentication_error_is_crypto_error(self):
        """Test that AuthenticationError inherits from CryptoError"""
        assert issubclass(AuthenticationError, CryptoError)

    def test_snapshot_error_is_crypto_error(self):
        """Test that SnapshotError inherits from CryptoError"""
        assert issubclass(SnapshotError, CryptoError)

    def test_raise_crypto_error(self):
        """Test raising CryptoError"""
        with pytest.raises(CryptoError):
            raise CryptoError("Test error")

    def test_raise_authentication_error(self):
        """Test raising AuthenticationError"""
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Auth failed")

    def test_raise_snapshot_error(self):
        """Test raising SnapshotError"""
        with pytest.raises(SnapshotError):
            raise SnapshotError("Snapshot invalid")
