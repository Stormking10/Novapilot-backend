import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env FIRST before importing anything else
load_dotenv(Path(__file__).resolve().parent / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes import scan, history, health, chat, advanced

app = FastAPI(
    title="OWASPilot API",
    description="AI-powered secure coding assistant backend",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(scan.router,   prefix="/api", tags=["scan"])
app.include_router(history.router, prefix="/api", tags=["history"])
app.include_router(chat.router,    prefix="/api", tags=["chat"])
app.include_router(advanced.router, prefix="/api", tags=["advanced"])

# Uvicorn server startup configuration
if __name__ == "__main__":
    import uvicorn
    
    # Get host and port from environment or use defaults
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    
    # Start Uvicorn server
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True
    )
