"""
Entrypoint for the fuzzer's own backend.

Run it:
    uvicorn app.main:app --reload --port 8000

(Separate from vulnerable-api, which is the *target* the fuzzer tests
against, typically on port 8001.)
"""

from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(
    title="AI-Powered API Security Fuzzer",
    description="Autonomous API security testing pipeline.",
    version="0.1.0",
)

app.include_router(router)
