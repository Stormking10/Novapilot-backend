import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Import the FastAPI app
from main import app

# Export as ASGI application for Vercel
asgi_app = app
