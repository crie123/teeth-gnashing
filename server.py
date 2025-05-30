from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import threading
import time
import random

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

state = {
    "tick": 0,
    "seed": random.randint(1, 1 << 30)
}

def update_tick(interval: float = 1.0):
    while True:
        state["tick"] = (state["tick"] + 1) % (1 << 31)
        time.sleep(interval)

@app.get("/snapshot", response_model=Snapshot)
def get_snapshot():
    return state

if __name__ == "__main__":
    threading.Thread(target=update_tick, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)
