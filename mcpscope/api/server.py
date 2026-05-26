from __future__ import annotations
import hmac
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from mcpscope.storage.store import Store
from mcpscope.config import Settings


API_KEY_HEADER = "X-API-Key"
DASHBOARD_COOKIE = "mcpscope_session"


class JSONLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "function": record.funcName,
            }
        )


def setup_logging(settings: Settings) -> None:
    root = logging.getLogger("mcpscope")
    root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    handler = logging.StreamHandler()
    if settings.log_json:
        handler.setFormatter(JSONLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    root.handlers.clear()
    root.addHandler(handler)


def _verify_session(request: Request, password: str) -> bool:
    cookie = request.cookies.get(DASHBOARD_COOKIE, "")
    if not cookie:
        return False
    expected = _session_value(password, request.client.host if request.client else "")
    return hmac.compare_digest(cookie, expected)


def _session_value(password: str, client_ip: str) -> str:
    h = hmac.new(password.encode(), client_ip.encode(), "sha256")
    return h.hexdigest()


def create_app(store: Store | None = None, settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings.load()
    setup_logging(cfg)
    logger = logging.getLogger("mcpscope.api")

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
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*", API_KEY_HEADER],
    )

    app.state.store = store or Store(db_path=cfg.db_path)
    app.state.auto_refresh = cfg.auto_refresh_seconds
    app.state.api_key = cfg.api_key
    app.state.dashboard_password = cfg.dashboard_password

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path

        if path in ("/health", "/api/health", "/api/login", "/api/logout"):
            return await call_next(request)

        if cfg.api_key and path.startswith("/api/") and request.method != "OPTIONS":
            req_key = request.headers.get(API_KEY_HEADER)
            if not hmac.compare_digest(req_key or "", cfg.api_key):
                logger.warning("API key rejected for %s", path)
                return JSONResponse(
                    status_code=401, content={"error": "Invalid or missing API key"}
                )

        if cfg.dashboard_password and not path.startswith("/api/"):
            if not _verify_session(request, cfg.dashboard_password):
                if path != "/login":
                    return RedirectResponse(url="/login")

        response = await call_next(request)
        return response

    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    if templates_dir.exists():
        from fastapi.templating import Jinja2Templates

        app.state.templates = Jinja2Templates(directory=str(templates_dir))

    from mcpscope.api.routes import router

    app.include_router(router)

    return app
