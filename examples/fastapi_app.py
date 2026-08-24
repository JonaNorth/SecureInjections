from fastapi import FastAPI

from secureinjections.middleware.fastapi import InputShieldASGIMiddleware
from secureinjections.quarantine import InMemoryQuarantine

app = FastAPI()
app.add_middleware(InputShieldASGIMiddleware, quarantine=InMemoryQuarantine())


@app.post("/messages")
async def create_message(payload: dict) -> dict:
    return {"accepted": True, "keys": sorted(payload)}
