"""Outcome rules: Python, not the LLM, decides the verdict. First matching rule wins."""

from __future__ import annotations

import pytest

from app.report import determine_outcome
from app.schemas import Evidence, LookupStatus, Outcome, ProviderName
from tests.conftest import ev

VT, UH, MB = ProviderName.VIRUSTOTAL, ProviderName.URLHAUS, ProviderName.MALWAREBAZAAR
FOUND, NOT_FOUND = LookupStatus.FOUND, LookupStatus.NOT_FOUND


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        # 1. A malware record wins, even when the other lookup failed.
        ([ev(VT, LookupStatus.RATE_LIMITED), ev(MB, FOUND)], Outcome.MALICIOUS_RECORD_FOUND),
        # 2. Engine detections without a record are a signal, not a confirmation.
        ([ev(VT, FOUND, malicious=3), ev(UH, NOT_FOUND)], Outcome.FLAGGED_BY_ENGINES),
        # 3. Never claim "clean" when a lookup failed.
        ([ev(VT, LookupStatus.TIMEOUT), ev(MB, NOT_FOUND)], Outcome.INCONCLUSIVE),
        # 4. A report with 0 detections and "no record" both count as completed lookups.
        ([ev(VT, FOUND, malicious=0), ev(UH, NOT_FOUND)], Outcome.NO_MALICIOUS_EVIDENCE_FOUND),
    ],
)
def test_outcome_rules(evidence: list[Evidence], expected: Outcome) -> None:
    assert determine_outcome(evidence) is expected
