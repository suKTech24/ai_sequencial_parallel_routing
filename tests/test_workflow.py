from __future__ import annotations

import asyncio
from typing import Any

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatResult

from app.providers import ProviderSet, URLhausProvider, VirusTotalProvider
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    LookupStatus,
    Outcome,
    ProviderName,
    SummarySource,
)
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


async def test_url_routes_to_virustotal_and_urlhaus(fake_providers: dict) -> None:  # type: ignore[type-arg]
    response = await run(build_graph(provider_set(fake_providers)), URL_REQ)
    assert len(fake_providers[VT].calls) == 1
    assert len(fake_providers[UH].calls) == 1
    assert fake_providers[MB].calls == []
    assert [e.provider for e in response.evidence] == [VT, UH]


async def test_hash_routes_to_virustotal_and_malwarebazaar(fake_providers: dict) -> None:  # type: ignore[type-arg]
    response = await run(build_graph(provider_set(fake_providers)), HASH_REQ)
    assert fake_providers[UH].calls == []
    assert len(fake_providers[MB].calls) == 1
    assert [e.provider for e in response.evidence] == [VT, MB]
    assert response.indicator.hash_type == "md5"


async def test_lookups_run_concurrently() -> None:
    # Each lookup waits for the other to start. Sequential execution would deadlock and time out.
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
    assert response.outcome is Outcome.NO_MALICIOUS_EVIDENCE_FOUND


async def test_timeout_in_one_branch_preserves_the_other() -> None:
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
    assert any("VirusTotal lookup timed out" in item for item in response.limitations)


async def test_positive_outcome_uses_llm_summary() -> None:
    fakes = {VT: FakeProvider(VT), UH: FakeProvider(UH, LookupStatus.FOUND), MB: FakeProvider(MB)}
    llm = GenericFakeChatModel(messages=iter([AIMessage(content="URLhaus lists this URL.")]))
    response = await run(build_graph(provider_set(fakes), llm), URL_REQ)
    assert response.summary_source is SummarySource.LLM
    assert response.summary == "URLhaus lists this URL."


class FailingChatModel(BaseChatModel):
    calls: int = 0

    @property
    def _llm_type(self) -> str:
        return "failing"

    def _generate(self, messages: list[BaseMessage], *args: Any, **kwargs: Any) -> ChatResult:
        self.calls += 1
        raise RuntimeError("model unavailable")


async def test_llm_failure_falls_back_to_template() -> None:
    fakes = {VT: FakeProvider(VT), UH: FakeProvider(UH, LookupStatus.FOUND), MB: FakeProvider(MB)}
    llm = FailingChatModel()
    response = await run(build_graph(provider_set(fakes), llm), URL_REQ)
    assert llm.calls == 1
    assert response.summary_source is SummarySource.TEMPLATE
    assert response.outcome is Outcome.MALICIOUS_RECORD_FOUND


async def test_non_positive_outcome_skips_llm(fake_providers: dict) -> None:  # type: ignore[type-arg]
    llm = FailingChatModel()
    response = await run(build_graph(provider_set(fake_providers), llm), HASH_REQ)
    assert llm.calls == 0
    assert response.summary_source is SummarySource.TEMPLATE
