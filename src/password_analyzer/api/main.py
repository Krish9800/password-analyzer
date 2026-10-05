"""FastAPI application entrypoint with security middleware and dashboard route."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

import password_analyzer
from password_analyzer.api.dashboard import get_dashboard_html
from password_analyzer.api.middleware import PrivacyHeaderMiddleware
from password_analyzer.api.routes import router

app = FastAPI(
    title="Password Intelligence Analyzer API",
    description=(
        "Defensive security REST API evaluating password entropy, combinatorial space, "
        "structural patterns, and offline resistance without persisting credentials."
    ),
    version=password_analyzer.__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enforce loopback CORS restrictions by default
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Register zero-log privacy header middleware
app.add_middleware(PrivacyHeaderMiddleware)

# Mount API routes
app.include_router(router)


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"], summary="Local Web Dashboard")
async def get_dashboard() -> HTMLResponse:
    """Serve embedded visual security dashboard."""
    return HTMLResponse(content=get_dashboard_html(), status_code=200)


@app.get("/health", tags=["Health"], include_in_schema=False)
async def root_health() -> dict[str, str]:
    """Root health alias."""
    return {
        "status": "healthy",
        "version": password_analyzer.__version__,
        "persistence_policy": "ZERO_STORAGE_LOCAL_IN_MEMORY",
    }
