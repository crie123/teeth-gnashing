# Array-Crypto

A production-ready Python library for dynamic snapshot-based encryption using server-client architecture.

## Features

- Dynamic snapshot-based encryption
- Secure handshake protocol
- Configurable server and client settings
- Support for both string and binary data encryption
- Thread-safe server implementation
- Async/await client API
- HMAC verification for snapshots
- Automatic session management
- Health check endpoint

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Server Configuration

Create a `server_config.json` file (will be created automatically with defaults if not present):

```json
{
    "secret_key": "base64_encoded_secret_key",
    "tick_interval": 1.0,
    "host": "0.0.0.0",
    "port": 8000,
    "hash_size": 16
}
```

## Client Configuration

Create a `client_config.json` file or pass configuration directly:

```json
{
    "server_url": "http://localhost:8000",
    "secret_key": "base64_encoded_secret_key",
    "max_drift": 60,
    "handshake_points": 8,
    "hash_size": 16
}
```

## Usage

### Starting the Server

```python
python server.py
```

The server will start on http://localhost:8000 by default.

### Using the Client

Basic usage with context manager:

```python
import asyncio
from client import CryptoClient, CryptoConfig

async def main():
    # Configuration can be loaded from file
    async with CryptoClient("client_config.json") as client:
        await client.authenticate()
        
        # Encrypt string data
        encrypted = await client.encrypt_message("Your secret message")
        decrypted = await client.decrypt_message(encrypted)
        print(decrypted.decode('utf-8'))

        # Encrypt binary data
        binary_data = b"Your binary data"
        encrypted = await client.encrypt_message(binary_data)
        decrypted = await client.decrypt_message(encrypted)

if __name__ == "__main__":
    asyncio.run(main())
```

Or with direct configuration:

```python
config = CryptoConfig(
    server_url="http://localhost:8000",
    secret_key=b"your_secret_key",  # Will be base64 encoded automatically
    max_drift=60  # Maximum allowed time drift in seconds
)

async with CryptoClient(config) as client:
    # Your encryption/decryption code here
    pass
```

## API Reference

### Server Endpoints

- `POST /handshake` - Initialize client authentication
  - Request body: `{"hash": "32_byte_hex_string"}`
  - Response: `{"status": "ok"}` or error

- `GET /snapshot` - Get current server snapshot
  - Response: `{"tick": int, "seed": int, "timestamp": int, "signature": string}`

- `GET /health` - Server health check
  - Response: `{"status": "healthy", "timestamp": int}`

### Client API

#### CryptoConfig

Configuration dataclass with the following fields:
- `server_url`: Server endpoint URL
- `secret_key`: HMAC secret key (bytes or base64 string)
- `max_drift`: Maximum allowed time drift in seconds
- `handshake_points`: Number of points for handshake function
- `hash_size`: Size of hash in bytes

#### CryptoClient

Main client class with the following methods:

- `async with CryptoClient(config) as client` - Create and manage client instance
- `await client.authenticate()` - Perform server handshake
- `await client.encrypt_message(data)` - Encrypt string or bytes
- `await client.decrypt_message(encrypted)` - Decrypt data
- `await client.close()` - Close client session

## Error Handling

The library provides specific exceptions for different error cases:

```python
try:
    async with CryptoClient(config) as client:
        await client.authenticate()
        encrypted = await client.encrypt_message("data")
except AuthenticationError:
    print("Authentication failed")
except SnapshotError:
    print("Invalid or expired snapshot")
except CryptoError:
    print("General encryption error")
```

## Security Considerations

1. The secret key should be kept secure and should be the same on both server and client
2. The server uses CORS middleware with "*" origins for development - configure appropriately for production
3. Time synchronization between server and client is important
4. The encryption method uses modular multiplication - suitable for data protection but not for critical security applications

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

See LICENSE file in the repository.