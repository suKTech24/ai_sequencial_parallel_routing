"""The LangGraph lessons: routing, real parallelism, failure isolation, LLM fallback."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatResult

from app.providers import ProviderSet, URLhausProvider, VirusTotalProvider
from app.schemas import AnalyzeRequest, AnalyzeResponse, LookupStatus, Outcome, ProviderName
from app.workflow import build_graph
from tests.conftest import FakeProvider

VT, UH, MB = ProviderName.VIRUSTOTAL, ProviderName.URLHAUS, ProviderName.MALWAREBAZAAR
URL_REQ = AnalyzeRequest(type="url", value="https://malware.example.com/payload.exe")
HASH_REQ = AnalyzeRequest(type="hash", value="44d88612fea8a8f36de82e1278abb02f")


def provider_set(fakes: dict[ProviderName, Any]) -> ProviderSet:
    return ProviderSet(virustotal=fakes[VT], urlhaus=fakes[UH], malwarebazaar=fakes[MB])


async def run(graph: Any, request: AnalyzeRequest) -> AnalyzeResponse:
    result = await graph.ainvoke({"request": request})
    response: AnalyzeResponse = result["response"]
    return response


async def test_routing_picks_providers_by_indicator_type(
    fake_providers: dict[ProviderName, FakeProvider],
) -> None:
    """Conditional routing: URL -> VirusTotal + URLhaus, hash -> VirusTotal + MalwareBazaar."""
    graph = build_graph(provider_set(fake_providers))

    await run(graph, URL_REQ)
    assert [len(fake_providers[p].calls) for p in (VT, UH, MB)] == [1, 1, 0]

    await run(graph, HASH_REQ)
    assert [len(fake_providers[p].calls) for p in (VT, UH, MB)] == [2, 1, 1]


async def test_lookups_really_run_in_parallel() -> None:
    """Each lookup waits for the other to start. Sequential execution would time out."""
    barrier = asyncio.Barrier(2)

    async def meet() -> None:
        async with asyncio.timeout(1):
            await barrier.wait()

    fakes = {
        VT: FakeProvider(VT, before=meet),  # type: ignore[arg-type]
        UH: FakeProvider(UH, before=meet),  # type: ignore[arg-type]
        MB: FakeProvider(MB),
    }
    response = await run(build_graph(provider_set(fakes)), URL_REQ)
    assert len(response.evidence) == 2


async def test_timeout_in_one_branch_keeps_the_other_result() -> None:
    """Providers never raise, so the join completes and URLhaus's record survives."""

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.virustotal.com":
            await asyncio.sleep(5)
        body = {"query_status": "ok", "threat": "malware_download"}
        return httpx.Response(200, json=body, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        providers = ProviderSet(
            virustotal=VirusTotalProvider(client, "k", timeout=0.05),
            urlhaus=URLhausProvider(client, "k", timeout=1),
            malwarebazaar=FakeProvider(MB),
        )
        response = await run(build_graph(providers), URL_REQ)

    statuses = {e.provider: e.lookup_status for e in response.evidence}
    assert statuses == {VT: LookupStatus.TIMEOUT, UH: LookupStatus.FOUND}
    assert response.outcome is Outcome.MALICIOUS_RECORD_FOUND


async def test_positive_outcome_uses_llm_summary() -> None:
    fakes = {VT: FakeProvider(VT), UH: FakeProvider(UH, LookupStatus.FOUND), MB: FakeProvider(MB)}
    llm = GenericFakeChatModel(messages=iter([AIMessage(content="URLhaus lists this URL.")]))
    response = await run(build_graph(provider_set(fakes), llm), URL_REQ)
    assert response.summary_source == "llm"
    assert response.summary == "URLhaus lists this URL."


class FailingChatModel(BaseChatModel):
    @property
    def _llm_type(self) -> str:
        return "failing"

    def _generate(self, messages: list[BaseMessage], *args: Any, **kwargs: Any) -> ChatResult:
        raise RuntimeError("model unavailable")


async def test_llm_failure_falls_back_to_template() -> None:
    """A broken model changes only the wording source, never the outcome."""
    fakes = {VT: FakeProvider(VT), UH: FakeProvider(UH, LookupStatus.FOUND), MB: FakeProvider(MB)}
    response = await run(build_graph(provider_set(fakes), FailingChatModel()), URL_REQ)
    assert response.summary_source == "template"
    assert response.outcome is Outcome.MALICIOUS_RECORD_FOUND
