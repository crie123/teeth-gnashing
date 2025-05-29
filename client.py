import aiohttp
import asyncio
import os
import time
from math import gcd

SERVER_URL = "http://localhost:8000"

async def get_snapshot():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{SERVER_URL}/snapshot") as response:
            return await response.json()

def derive_key_from_snapshot(snapshot, salt: bytes):
    seed = snapshot['seed']
    tick = snapshot['tick'] ^ int.from_bytes(salt[:4], 'little')  # Salt affects the tick

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
    result = bytearray(salt)  # Add salt to the beginning of the encrypted stream
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

async def encrypt_message(message: str):
    snapshot = await get_snapshot()

    salt = int(time.time()).to_bytes(8, 'little') + os.urandom(8)
    tick_key = derive_key_from_snapshot(snapshot, salt)

    input_bytes = bytearray(message.encode('utf-8'))
    encrypted = encrypt_stream(input_bytes, tick_key, salt)
    return encrypted

async def decrypt_message(encrypted: bytes):
    snapshot = await get_snapshot()
    salt = encrypted[:16]
    tick_key = derive_key_from_snapshot(snapshot, salt)
    decrypted = decrypt_stream(encrypted[16:], tick_key)
    return decrypted.decode('utf-8')

async def tick_refresher(update_interval: int, callback):
    while True:
        snapshot = await get_snapshot()
        await callback(snapshot)
        await asyncio.sleep(update_interval)

async def main():
    message = "это пример шифрования с динамическим tick"

    # Example of encrypting and decrypting a message
    encrypted = await encrypt_message(message)
    print("Encrypted:", encrypted)

    decrypted = await decrypt_message(encrypted)
    print("Decrypted:", decrypted)

    # Example of using tick refresher
    async def on_tick_update(snapshot):
        print(f"[Tick обновлен] seed={snapshot['seed']}, tick={snapshot['tick']}")

    # Launch the tick refresher(will stop after 10 seconds)
    task = asyncio.create_task(tick_refresher(1, on_tick_update))
    await asyncio.sleep(10)
    task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
