import pytest
import json
import base64
from pathlib import Path
from server import ServerConfig, ServerState, load_config
import tempfile
import os


class TestServerConfig:
    """Test ServerConfig initialization and validation"""

    def test_config_initialization(self, server_config_dict):
        """Test ServerConfig initialization with valid data"""
        config = ServerConfig(**server_config_dict)
        assert config.secret_key == server_config_dict["secret_key"]
        assert config.tick_interval == 1.0
        assert config.host == "0.0.0.0"
        assert config.port == 8000

    def test_config_defaults(self):
        """Test ServerConfig default values"""
        config = ServerConfig(
            secret_key=base64.b64encode(b"test_key").decode()
        )
        assert config.tick_interval == 1.0
        assert config.host == "0.0.0.0"
        assert config.port == 8000
        assert config.hash_size == 32
        assert config.array_size == 256

    def test_config_custom_values(self):
        """Test ServerConfig with custom values"""
        config = ServerConfig(
            secret_key=base64.b64encode(b"test_key").decode(),
            tick_interval=2.0,
            host="127.0.0.1",
            port=9000,
            hash_size=64,
            array_size=512
        )
        assert config.tick_interval == 2.0
        assert config.host == "127.0.0.1"
        assert config.port == 9000
        assert config.hash_size == 64
        assert config.array_size == 512

    def test_config_secret_key_required(self):
        """Test that secret_key is required"""
        with pytest.raises(Exception):  # Pydantic validation error
            ServerConfig()


class TestServerState:
    """Test ServerState class"""

    def test_state_initialization(self, server_config_dict):
        """Test ServerState initialization"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        assert state.tick == 0
        assert state.seed > 0
        assert len(state.authenticated_hashes) == 0
        assert state.config == config

    def test_increment_tick(self, server_config_dict):
        """Test tick increment"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        initial_tick = state.tick
        state.increment_tick()
        assert state.tick == initial_tick + 1

    def test_increment_tick_wraps_at_boundary(self, server_config_dict):
        """Test that tick wraps at 2^31"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        state.tick = (1 << 31) - 1
        state.increment_tick()
        assert state.tick == 0

    def test_add_hash(self, server_config_dict):
        """Test adding authenticated hash"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        test_hash = "a" * 64
        state.add_hash(test_hash)
        
        assert test_hash in state.authenticated_hashes

    def test_is_hash_authenticated_true(self, server_config_dict):
        """Test checking authenticated hash exists"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        test_hash = "b" * 64
        state.add_hash(test_hash)
        
        assert state.is_hash_authenticated(test_hash) is True

    def test_is_hash_authenticated_false(self, server_config_dict):
        """Test checking non-existent hash"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        assert state.is_hash_authenticated("c" * 64) is False

    def test_multiple_hashes(self, server_config_dict):
        """Test adding and checking multiple hashes"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        hashes = ["d" * 64, "e" * 64, "f" * 64]
        for h in hashes:
            state.add_hash(h)
        
        for h in hashes:
            assert state.is_hash_authenticated(h) is True

    def test_seed_changes_periodically(self, server_config_dict):
        """Test that seed changes after 100 ticks"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        initial_seed = state.seed
        
        # Increment 100 times
        for _ in range(100):
            state.increment_tick()
        
        # Seed should have changed
        assert state.seed != initial_seed


class TestLoadConfig:
    """Test configuration loading from file"""

    def test_load_config_creates_default(self, temp_dir):
        """Test that load_config creates default config if file doesn't exist"""
        config_path = os.path.join(temp_dir, "server_config.json")
        
        config = load_config(config_path)
        
        assert config.secret_key is not None
        assert config.tick_interval == 1.0
        assert Path(config_path).exists()

    def test_load_config_from_existing_file(self, temp_dir):
        """Test loading config from existing file"""
        config_path = os.path.join(temp_dir, "server_config.json")
        
        # Create config file
        config_data = {
            "secret_key": base64.b64encode(b"custom_secret").decode(),
            "tick_interval": 2.5,
            "host": "127.0.0.1",
            "port": 9000,
            "hash_size": 64,
            "array_size": 512
        }
        
        with open(config_path, 'w') as f:
            json.dump(config_data, f)
        
        config = load_config(config_path)
        
        assert config.tick_interval == 2.5
        assert config.host == "127.0.0.1"
        assert config.port == 9000
        assert config.hash_size == 64
        assert config.array_size == 512

    def test_load_config_invalid_file(self, temp_dir):
        """Test loading config from invalid JSON file"""
        config_path = os.path.join(temp_dir, "bad_config.json")
        
        # Write invalid JSON
        with open(config_path, 'w') as f:
            f.write("{ invalid json }")
        
        with pytest.raises(Exception):  # Should raise RuntimeError
            load_config(config_path)

    def test_load_config_default_path(self, temp_dir, monkeypatch):
        """Test loading config from default path"""
        # Change to temp directory
        monkeypatch.chdir(temp_dir)
        
        # This should create default config in current directory
        config = load_config("server_config.json")
        
        assert config.secret_key is not None
        assert Path("server_config.json").exists()


class TestServerConfigFormat:
    """Test server config file format and persistence"""

    def test_config_file_contains_required_fields(self, temp_dir):
        """Test that created config file contains all required fields"""
        config_path = os.path.join(temp_dir, "server_config.json")
        
        config = load_config(config_path)
        
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        required_fields = [
            "secret_key",
            "tick_interval",
            "host",
            "port",
            "hash_size",
            "array_size"
        ]
        
        for field in required_fields:
            assert field in config_data

    def test_config_file_is_valid_json(self, temp_dir):
        """Test that created config file is valid JSON"""
        config_path = os.path.join(temp_dir, "server_config.json")
        
        config = load_config(config_path)
        
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        assert isinstance(config_data, dict)

    def test_config_secret_key_is_base64(self, temp_dir):
        """Test that secret key in config file is base64 encoded"""
        config_path = os.path.join(temp_dir, "server_config.json")
        
        config = load_config(config_path)
        
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        secret_key_str = config_data["secret_key"]
        
        # Should be decodable as base64
        decoded = base64.b64decode(secret_key_str)
        assert isinstance(decoded, bytes)


class TestThreadSafety:
    """Test thread safety of ServerState"""

    def test_concurrent_hash_additions(self, server_config_dict):
        """Test that hash additions are thread-safe"""
        import threading
        
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        def add_hashes(start_idx):
            for i in range(10):
                hash_val = f"{start_idx:02d}{i:02d}" + "a" * 60
                state.add_hash(hash_val)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=add_hashes, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should have 50 hashes (5 threads * 10 hashes each)
        assert len(state.authenticated_hashes) == 50

    def test_concurrent_tick_increments(self, server_config_dict):
        """Test that tick increments are thread-safe"""
        import threading
        
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        def increment_ticks(count):
            for _ in range(count):
                state.increment_tick()
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment_ticks, args=(10,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should have incremented exactly 100 times
        assert state.tick == 100


class TestServerConfigEdgeCases:
    """Test edge cases in server configuration"""

    def test_config_with_zero_tick_interval(self):
        """Test config with zero tick interval"""
        config = ServerConfig(
            secret_key=base64.b64encode(b"test").decode(),
            tick_interval=0.0
        )
        assert config.tick_interval == 0.0

    def test_config_with_negative_port(self):
        """Test config with invalid port number"""
        # Pydantic might validate this, but we test the raw config
        config = ServerConfig(
            secret_key=base64.b64encode(b"test").decode(),
            port=-1
        )
        assert config.port == -1

    def test_config_with_large_hash_size(self):
        """Test config with large hash size"""
        config = ServerConfig(
            secret_key=base64.b64encode(b"test").decode(),
            hash_size=256
        )
        assert config.hash_size == 256

    def test_config_with_large_array_size(self):
        """Test config with large array size"""
        config = ServerConfig(
            secret_key=base64.b64encode(b"test").decode(),
            array_size=4096
        )
        assert config.array_size == 4096

    def test_state_with_max_tick_value(self, server_config_dict):
        """Test state at maximum tick value"""
        config = ServerConfig(**server_config_dict)
        state = ServerState(config)
        
        state.tick = (1 << 31) - 2
        state.increment_tick()
        state.increment_tick()
        
        # Should wrap to 0
        assert state.tick == 0
