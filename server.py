from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import threading
import time
import random
import hashlib
import hmac
import base64

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Snapshot(BaseModel):
    tick: int
    seed: int
    timestamp: int
    signature: str

class HandshakeRequest(BaseModel):
    hash: str

state = {
    "tick": 0,
    "seed": random.randint(1, 1 << 30),
    "authenticated_hashes": set()
}

SECRET_KEY = b"super_secret_key_for_hmac"

def update_tick(interval: float = 1.0):
    while True:
        state["tick"] = (state["tick"] + 1) % (1 << 31)
        time.sleep(interval)

def sign_snapshot(tick: int, seed: int, timestamp: int) -> str:
    message = f"{tick}|{seed}|{timestamp}".encode()
    sig = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()

@app.post("/handshake")
async def handshake(req: HandshakeRequest):
    h = req.hash.lower()
    if not h or len(h) != 32:
        return {"status": "invalid"}
    state["authenticated_hashes"].add(h)
    return {"status": "ok"}

@app.get("/snapshot")
async def get_snapshot(request: Request):
    timestamp = int(time.time())
    tick = state["tick"]
    seed = state["seed"]
    signature = sign_snapshot(tick, seed, timestamp)
    return Snapshot(tick=tick, seed=seed, timestamp=timestamp, signature=signature)

if __name__ == "__main__":
    threading.Thread(target=update_tick, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)
