"""LangGraph workflow: sequential steps, parallel provider fan-out, and conditional routing.

validate -> route_by_type -> {virustotal, urlhaus | malwarebazaar} (parallel)
         -> evaluate -> route_by_outcome -> write_summary | write_status -> build_response
"""

from __future__ import annotations

import asyncio
import logging
import operator
from typing import Annotated, Any, Final, Literal, TypedDict

from langchain_core.language_models import BaseChatModel
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.providers import Provider, ProviderSet
from app.report import (
    POSITIVE_OUTCOMES,
    build_limitations,
    determine_outcome,
    llm_summary,
    template_summary,
)
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    Evidence,
    Indicator,
    IndicatorType,
    Outcome,
    ProviderName,
    SummarySource,
)

logger = logging.getLogger(__name__)

VALIDATE: Final = "validate"
VIRUSTOTAL: Final = "virustotal"
URLHAUS: Final = "urlhaus"
MALWAREBAZAAR: Final = "malwarebazaar"
EVALUATE: Final = "evaluate"
WRITE_SUMMARY: Final = "write_summary"
WRITE_STATUS: Final = "write_status"
BUILD_RESPONSE: Final = "build_response"

PROVIDER_ROUTES: dict[IndicatorType, list[str]] = {
    IndicatorType.URL: [VIRUSTOTAL, URLHAUS],
    IndicatorType.HASH: [VIRUSTOTAL, MALWAREBAZAAR],
}
FIXTURE_NOTICE: Final = (
    "Offline fixture mode: results come from synthetic test data, not live provider lookups. "
    "Set PROVIDER_MODE=live to query real providers."
)
_PROVIDER_ORDER = {name: i for i, name in enumerate(ProviderName)}


class GraphState(TypedDict, total=False):
    request: AnalyzeRequest
    indicator: Indicator
    # Reducer: each parallel branch appends its own Evidence; the join sees both.
    evidence: Annotated[list[Evidence], operator.add]
    outcome: Outcome
    limitations: list[str]
    summary: str
    summary_source: SummarySource
    response: AnalyzeResponse


StateUpdate = dict[str, Any]


def build_graph(
    providers: ProviderSet,
    llm: BaseChatModel | None = None,
    llm_timeout: float = 20.0,
    fixture_mode: bool = False,
) -> CompiledStateGraph[GraphState, Any, GraphState, GraphState]:
    async def validate(state: GraphState) -> StateUpdate:
        return {"indicator": Indicator.from_request(state["request"])}

    def route_by_type(state: GraphState) -> list[str]:
        return PROVIDER_ROUTES[state["indicator"].type]

    def lookup_node(provider: Provider) -> Any:
        async def lookup(state: GraphState) -> StateUpdate:
            return {"evidence": [await provider.lookup(state["indicator"])]}

        return lookup

    async def evaluate(state: GraphState) -> StateUpdate:
        evidence = state.get("evidence", [])
        limitations = build_limitations(evidence)
        if fixture_mode:
            limitations.insert(0, FIXTURE_NOTICE)
        return {"outcome": determine_outcome(evidence), "limitations": limitations}

    def route_by_outcome(state: GraphState) -> Literal["write_summary", "write_status"]:
        return WRITE_SUMMARY if state["outcome"] in POSITIVE_OUTCOMES else WRITE_STATUS

    def _template(state: GraphState) -> StateUpdate:
        summary = template_summary(state["indicator"], state["outcome"], _sorted(state["evidence"]))
        return {"summary": summary, "summary_source": SummarySource.TEMPLATE}

    async def write_summary(state: GraphState) -> StateUpdate:
        if llm is None:
            return _template(state)
        try:
            async with asyncio.timeout(llm_timeout):
                summary = await llm_summary(
                    llm,
                    state["indicator"],
                    state["outcome"],
                    _sorted(state["evidence"]),
                    state["limitations"],
                )
        except Exception:
            logger.warning("LLM summary failed; using template", exc_info=True)
            return _template(state)
        return {"summary": summary, "summary_source": SummarySource.LLM}

    async def write_status(state: GraphState) -> StateUpdate:
        return _template(state)

    async def build_response(state: GraphState) -> StateUpdate:
        response = AnalyzeResponse(
            indicator=state["indicator"],
            outcome=state["outcome"],
            evidence=_sorted(state["evidence"]),
            limitations=state["limitations"],
            summary=state["summary"],
            summary_source=state["summary_source"],
        )
        return {"response": response}

    graph = StateGraph(GraphState)
    graph.add_node(VALIDATE, validate)
    graph.add_node(VIRUSTOTAL, lookup_node(providers.virustotal))
    graph.add_node(URLHAUS, lookup_node(providers.urlhaus))
    graph.add_node(MALWAREBAZAAR, lookup_node(providers.malwarebazaar))
    graph.add_node(EVALUATE, evaluate)
    graph.add_node(WRITE_SUMMARY, write_summary)
    graph.add_node(WRITE_STATUS, write_status)
    graph.add_node(BUILD_RESPONSE, build_response)

    graph.add_edge(START, VALIDATE)
    # Returning two node names fans out; both run in the same superstep, so EVALUATE
    # runs once, after both branches have finished.
    graph.add_conditional_edges(VALIDATE, route_by_type, [VIRUSTOTAL, URLHAUS, MALWAREBAZAAR])
    for node in (VIRUSTOTAL, URLHAUS, MALWAREBAZAAR):
        graph.add_edge(node, EVALUATE)
    graph.add_conditional_edges(EVALUATE, route_by_outcome, [WRITE_SUMMARY, WRITE_STATUS])
    graph.add_edge(WRITE_SUMMARY, BUILD_RESPONSE)
    graph.add_edge(WRITE_STATUS, BUILD_RESPONSE)
    graph.add_edge(BUILD_RESPONSE, END)

    return graph.compile()


def _sorted(evidence: list[Evidence]) -> list[Evidence]:
    """Stable, provider-ordered evidence regardless of which branch finished first."""
    return sorted(evidence, key=lambda e: _PROVIDER_ORDER[e.provider])
