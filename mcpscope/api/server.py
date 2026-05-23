from __future__ import annotations
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from typing import Optional

from mcpscope.storage.store import Store
from mcpscope.config import Settings


API_KEY_HEADER = "X-API-Key"


def create_app(store: Store | None = None, settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings.load()

    app = FastAPI(
        title="MCP-Scope API",
        description="Unified security dashboard for MCP/A2A scanner results",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*", API_KEY_HEADER],
    )

    app.state.store = store or Store(db_path=cfg.db_path)
    app.state.auto_refresh = cfg.auto_refresh_seconds
    app.state.api_key = cfg.api_key

    @app.middleware("http")
    async def check_api_key(request: Request, call_next):
        if cfg.api_key:
            if request.url.path.startswith("/api/") and request.method != "OPTIONS":
                req_key = request.headers.get(API_KEY_HEADER) or request.query_params.get("api_key")
                if req_key != cfg.api_key:
                    from fastapi.responses import JSONResponse
                    return JSONResponse(status_code=401, content={"error": "Invalid or missing API key"})
        response = await call_next(request)
        return response

    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    if templates_dir.exists():
        from fastapi.templating import Jinja2Templates
        app.state.templates = Jinja2Templates(directory=str(templates_dir))

    from mcpscope.api.routes import router
    app.include_router(router)

    return app
