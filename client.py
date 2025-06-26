import aiohttp
import asyncio
import os
import time
import hashlib
import random
from math import gcd
import hmac
import base64

SERVER_URL = "http://localhost:8000"
SECRET_KEY = b"super_secret_key_for_hmac"
MAX_DRIFT = 10  # seconds

def generate_function_points(n=8):
    return [(random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(0, 1)) for _ in range(n)]

def hash_function_points(points):
    flat = b"".join([
        float(x).hex().encode() + float(y).hex().encode() + float(z).hex().encode() + float(v).hex().encode()
        for x, y, z, v in points
    ])
    return hashlib.blake2s(flat, digest_size=16).digest()

async def authenticate_with_function(session):
    points = generate_function_points()
    func_hash = hash_function_points(points)
    payload = {"hash": func_hash.hex()}
    async with session.post(f"{SERVER_URL}/handshake", json=payload) as resp:
        if resp.status != 200:
            raise Exception("Authentication failed")
        return points  # dots remain only on the client
    

def verify_snapshot_signature(tick, seed, timestamp, signature):
    msg = f"{tick}|{seed}|{timestamp}".encode()
    expected = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
    return base64.b64encode(expected).decode() == signature

async def get_snapshot():
    async with aiohttp.ClientSession() as session:
        await authenticate_with_function(session)
        async with session.get(f"{SERVER_URL}/snapshot") as response:
            snap = await response.json()
            now = int(time.time())
            if abs(now - snap["timestamp"]) > MAX_DRIFT:
                raise ValueError("Snapshot expired or too far in future")
            if not verify_snapshot_signature(snap["tick"], snap["seed"], snap["timestamp"], snap["signature"]):
                raise ValueError("Invalid snapshot signature")
            return snap

def derive_key_from_snapshot(snapshot, salt: bytes):
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
        while gcd(tick_b, 256) != 1:
            tick_b = (tick_b + 1) % 256
            if tick_b == 0:
                tick_b = 1
        tick_bytes.append(tick_b)

    return tick_bytes

def encrypt_stream(byte_stream, tick_key, salt):
    result = bytearray(salt)
    for i, b in enumerate(byte_stream):
        t = tick_key[i % 64]
        result.append((b * t) % 256)
    return result

def decrypt_stream(encrypted_stream, tick_key):
    result = bytearray()
    for i, b in enumerate(encrypted_stream):
        t = tick_key[i % 64]
        t_inv = pow(t, -1, 256)
        result.append((b * t_inv) % 256)
    return result

def fast_hash(data: bytes, digest_size=16):
    return hashlib.blake2s(data, digest_size=digest_size).digest()

async def encrypt_message(message: str):
    snapshot = await get_snapshot()
    salt = int(time.time()).to_bytes(8, 'little') + os.urandom(8)
    tick_key = derive_key_from_snapshot(snapshot, salt)

    input_bytes = bytearray(message.encode('utf-8'))
    encrypted = encrypt_stream(input_bytes, tick_key, salt)
    hashed = fast_hash(encrypted)
    return hashed + encrypted

async def decrypt_message(encrypted: bytes):
    snapshot = await get_snapshot()
    recv_hash = encrypted[:16]
    salt = encrypted[16:32]
    payload = encrypted[32:]

    tick_key = derive_key_from_snapshot(snapshot, salt)
    decrypted = decrypt_stream(payload, tick_key)

    actual_hash = fast_hash(encrypted[16:])
    if recv_hash != actual_hash:
        raise ValueError("Hash mismatch! Possible tampering or corruption.")

    return decrypted.decode('utf-8')

async def main():
    message = "это пример шифрования с динамическим tick, хэшем и handshake-функцией"

    encrypted = await encrypt_message(message)
    print("Encrypted:", encrypted)

    decrypted = await decrypt_message(encrypted)
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    asyncio.run(main())
