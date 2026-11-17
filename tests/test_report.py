from __future__ import annotations

import pytest

from app.report import build_limitations, determine_outcome, template_summary
from app.schemas import LookupStatus, Outcome, ProviderName
from tests.conftest import MD5, URL, ev

VT, UH, MB = ProviderName.VIRUSTOTAL, ProviderName.URLHAUS, ProviderName.MALWAREBAZAAR
FOUND, NOT_FOUND = LookupStatus.FOUND, LookupStatus.NOT_FOUND


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        # Malware record wins, even when the other lookup failed.
        ([ev(VT, LookupStatus.RATE_LIMITED), ev(MB, FOUND)], Outcome.MALICIOUS_RECORD_FOUND),
        ([ev(VT, FOUND, malicious=12), ev(UH, FOUND)], Outcome.MALICIOUS_RECORD_FOUND),
        # Engine-only signal.
        ([ev(VT, FOUND, malicious=3), ev(UH, NOT_FOUND)], Outcome.FLAGGED_BY_ENGINES),
        ([ev(VT, FOUND, malicious=3), ev(UH, LookupStatus.TIMEOUT)], Outcome.FLAGGED_BY_ENGINES),
        # Incomplete with nothing positive.
        ([ev(VT, LookupStatus.TIMEOUT), ev(MB, NOT_FOUND)], Outcome.INCONCLUSIVE),
        ([ev(VT, FOUND, malicious=0), ev(UH, LookupStatus.ERROR)], Outcome.INCONCLUSIVE),
        ([], Outcome.INCONCLUSIVE),
        # Completed and clean: a zero-detection report and "no record" are both completed.
        ([ev(VT, FOUND, malicious=0), ev(UH, NOT_FOUND)], Outcome.NO_MALICIOUS_EVIDENCE_FOUND),
        ([ev(VT, NOT_FOUND), ev(MB, NOT_FOUND)], Outcome.NO_MALICIOUS_EVIDENCE_FOUND),
    ],
)
def test_determine_outcome(evidence: list, expected: Outcome) -> None:  # type: ignore[type-arg]
    assert determine_outcome(evidence) is expected


def test_limitations_list_failures_and_missing_vt_report() -> None:
    limitations = build_limitations([ev(VT, NOT_FOUND), ev(MB, LookupStatus.TIMEOUT)])
    assert limitations == [
        "VirusTotal has no existing report for this indicator.",
        "MalwareBazaar lookup timed out; its evidence is unavailable.",
    ]


def test_template_for_record_with_rate_limited_vt() -> None:
    evidence = [ev(VT, LookupStatus.RATE_LIMITED), ev(MB, FOUND, signature="EICAR-Test-File")]
    summary = template_summary(MD5, Outcome.MALICIOUS_RECORD_FOUND, evidence)
    assert summary == (
        "MalwareBazaar (EICAR-Test-File) returned a matching malware record for this MD5 hash. "
        "VirusTotal was rate-limited, so cross-source confirmation is unavailable."
    )


def test_template_for_engine_flag_includes_counts() -> None:
    evidence = [
        ev(VT, FOUND, malicious=4, suspicious=2, harmless=65, undetected=22),
        ev(UH, NOT_FOUND),
    ]
    summary = template_summary(URL, Outcome.FLAGGED_BY_ENGINES, evidence)
    assert "4 of 93 engines" in summary
    assert "engine signal rather than a confirmed record" in summary


def test_template_for_clean_and_inconclusive() -> None:
    clean = template_summary(
        URL,
        Outcome.NO_MALICIOUS_EVIDENCE_FOUND,
        [ev(VT, FOUND, malicious=0, harmless=70), ev(UH, NOT_FOUND)],
    )
    assert clean.startswith("VirusTotal and URLhaus completed lookups for this URL")

    incomplete = template_summary(
        MD5, Outcome.INCONCLUSIVE, [ev(VT, LookupStatus.TIMEOUT), ev(MB, NOT_FOUND)]
    )
    assert "check is incomplete" in incomplete
    assert "VirusTotal timed out" in incomplete
