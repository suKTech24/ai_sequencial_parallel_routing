from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas import AnalyzeRequest, HashType, Indicator


def test_url_preserves_path_and_query() -> None:
    req = AnalyzeRequest(type="url", value="  https://Example.org/a/B?x=1&y=2#frag ")
    assert req.value == "https://Example.org/a/B?x=1&y=2#frag"


@pytest.mark.parametrize(
    "value",
    ["ftp://example.org/file", "javascript:alert(1)", "https://", "example.org", "http://a b.com/"],
)
def test_url_rejects_invalid(value: str) -> None:
    with pytest.raises(ValidationError):
        AnalyzeRequest(type="url", value=value)


@pytest.mark.parametrize(
    ("value", "hash_type"),
    [
        ("44D88612FEA8A8F36DE82E1278ABB02F", HashType.MD5),
        ("3395856CE81F2B7382DEE72602F798B642F14140", HashType.SHA1),
        ("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", HashType.SHA256),
    ],
)
def test_hash_is_lowercased_and_classified(value: str, hash_type: HashType) -> None:
    indicator = Indicator.from_request(AnalyzeRequest(type="hash", value=value))
    assert indicator.value == value.lower()
    assert indicator.hash_type is hash_type


@pytest.mark.parametrize("value", ["abc", "z" * 32, "a" * 33, "a" * 65, ""])
def test_hash_rejects_invalid(value: str) -> None:
    with pytest.raises(ValidationError):
        AnalyzeRequest(type="hash", value=value)


def test_rejects_unknown_type_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AnalyzeRequest(type="ip", value="1.2.3.4")
    with pytest.raises(ValidationError):
        AnalyzeRequest.model_validate({"type": "url", "value": "https://a.com", "extra": 1})
