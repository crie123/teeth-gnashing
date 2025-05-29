from fastapi import FastAPI
from fastapi.responses import JSONResponse
import asyncio
import uvicorn
import time

app = FastAPI()

seed = 123456789  # Can be secretly set or updated
tick = 0

async def tick_updater():
    global tick
    while True:
        await asyncio.sleep(5)  # Update interval in seconds
        tick += 1

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(tick_updater())

@app.get("/snapshot")
async def get_snapshot():
    return JSONResponse({"seed": seed, "tick": tick})

@app.post("/seed/{new_seed}")
async def update_seed(new_seed: int):
    global seed
    seed = new_seed
    return {"message": "Seed updated", "new_seed": seed}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
