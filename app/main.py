"""FastAPI entry point: `uvicorn app.main:app --reload`."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Request

from app.config import ProviderMode, Settings, get_settings
from app.llm import build_chat_model
from app.providers import build_providers, create_http_client
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.workflow import build_graph

logger = logging.getLogger(__name__)
router = APIRouter()


def get_graph(request: Request) -> Any:
    return request.app.state.graph


@router.post("/analyze", response_model=AnalyzeResponse, summary="Enrich one URL or file hash")
async def analyze(
    body: AnalyzeRequest, graph: Annotated[Any, Depends(get_graph)]
) -> AnalyzeResponse:
    result = await graph.ainvoke({"request": body})
    response: AnalyzeResponse = result["response"]
    return response


@router.get("/health", summary="Liveness and configuration check")
async def health(request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    return {
        "status": "ok",
        "provider_mode": settings.provider_mode,
        "llm_enabled": request.app.state.llm_enabled,
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(
            level=settings.log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        async with create_http_client(settings) as client:
            llm = build_chat_model(settings)
            app.state.settings = settings
            app.state.llm_enabled = llm is not None
            fixture_mode = settings.provider_mode is ProviderMode.FIXTURES
            if fixture_mode:
                logger.warning(
                    "PROVIDER_MODE=fixtures: serving synthetic data, no live provider lookups"
                )
            app.state.graph = build_graph(
                build_providers(settings, client),
                llm,
                settings.llm_timeout_seconds,
                fixture_mode=fixture_mode,
            )
            yield

    app = FastAPI(
        title="IOC Enrichment Assistant",
        version="0.1.0",
        description=(
            "Enrich one URL or file hash against two threat-intelligence sources in parallel "
            "and return an analyst report. Submitted indicators are treated as data only."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()
