from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import threading
import time
import random
import hashlib
import hmac
import base64
import json
from pathlib import Path
from typing import Optional, Set
import secrets

class ServerConfig(BaseModel):
    secret_key: str = Field(..., description="Base64 encoded secret key for HMAC")
    tick_interval: float = Field(default=1.0, description="Interval for tick updates in seconds")
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    hash_size: int = Field(default=32, description="Size of hash in bytes")
    array_size: int = Field(default=256, description="Size of array for key derivation")

class Snapshot(BaseModel):
    tick: int
    seed: int
    timestamp: int
    signature: str

class HandshakeRequest(BaseModel):
    hash: str

class ServerState:
    def __init__(self, config: ServerConfig):
        self.tick: int = 0
        self.seed: int = random.randint(1, 1 << 30)
        self.authenticated_hashes: Set[str] = set()
        self._lock = threading.Lock()
        self.config = config

    def increment_tick(self):
        with self._lock:
            self.tick = (self.tick + 1) % (1 << 31)
            if self.tick % 100 == 0:  # Периодически обновляем seed для большей энтропии
                self.seed = random.randint(1, 1 << 30)

    def add_hash(self, hash_value: str) -> None:
        with self._lock:
            self.authenticated_hashes.add(hash_value)

    def is_hash_authenticated(self, hash_value: str) -> bool:
        with self._lock:
            return hash_value in self.authenticated_hashes

app = FastAPI(title="Array-Crypto Server",
             description="Dynamic snapshot-based encryption server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_config(config_path: str = "server_config.json") -> ServerConfig:
    try:
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                config_data = json.load(f)
        else:
            config_data = {
                "secret_key": base64.b64encode(b"super_secret_key_for_hmac").decode(),
                "tick_interval": 1.0,
                "host": "0.0.0.0",
                "port": 8000,
                "hash_size": 32,
                "array_size": 256
            }
            # Save default config
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
        
        return ServerConfig(**config_data)
    except Exception as e:
        raise RuntimeError(f"Failed to load config: {str(e)}")

config = load_config()
state = ServerState(config)

def update_tick(interval: float = 1.0):
    while True:
        state.increment_tick()
        time.sleep(interval)

def sign_snapshot(tick: int, seed: int, timestamp: int) -> str:
    message = f"{tick}|{seed}|{timestamp}".encode()
    sig = hmac.new(base64.b64decode(config.secret_key), message, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()

@app.post("/handshake")
async def handshake(req: HandshakeRequest):
    h = req.hash.lower()
    # Обновляем проверку для 32-байтового хеша (64 символа в hex)
    if not h or len(h) != 64:
        raise HTTPException(status_code=400, detail="Invalid hash format")
    
    try:
        # Проверяем, что это валидный hex
        bytes.fromhex(h)
        state.add_hash(h)
        return {"status": "ok"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hash hex encoding")

@app.get("/snapshot")
async def get_snapshot(request: Request):
    timestamp = int(time.time())
    signature = sign_snapshot(state.tick, state.seed, timestamp)
    return Snapshot(
        tick=state.tick,
        seed=state.seed,
        timestamp=timestamp,
        signature=signature
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "tick": state.tick,
        "authenticated_clients": len(state.authenticated_hashes)
    }

if __name__ == "__main__":
    threading.Thread(target=update_tick, args=(config.tick_interval,), daemon=True).start()
    uvicorn.run(app, host=config.host, port=config.port)
