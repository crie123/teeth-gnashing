import pytest
import asyncio
import json
import base64
from pathlib import Path
import tempfile
import shutil


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test configs"""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def server_config_dict():
    """Default server configuration for tests"""
    return {
        "secret_key": base64.b64encode(b"super_secret_key_for_hmac").decode(),
        "tick_interval": 1.0,
        "host": "0.0.0.0",
        "port": 8000,
        "hash_size": 32,
        "array_size": 256
    }


@pytest.fixture
def client_config_dict():
    """Default client configuration for tests"""
    return {
        "server_url": "http://localhost:8000",
        "secret_key": base64.b64encode(b"super_secret_key_for_hmac").decode(),
        "max_drift": 60,
        "handshake_points": 8,
        "hash_size": 32,
        "array_size": 256
    }
