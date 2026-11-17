"""Chat model construction. Returns None when no model is configured or it cannot start."""

from __future__ import annotations

import logging

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel

from app.config import Settings

logger = logging.getLogger(__name__)


def build_chat_model(settings: Settings) -> BaseChatModel | None:
    if not settings.llm_model:
        logger.info("LLM_MODEL not set; summaries will use templates")
        return None
    try:
        model = init_chat_model(
            settings.llm_model, model_provider=settings.llm_provider, temperature=0
        )
    except Exception:
        logger.warning(
            "Could not initialise chat model %r; summaries will use templates",
            settings.llm_model,
            exc_info=True,
        )
        return None
    logger.info("Using chat model %r for summaries", settings.llm_model)
    return model
