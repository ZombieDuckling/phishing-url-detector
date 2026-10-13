import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detector import is_ip, load_urls, score_url, verdict


def test_verdict_boundaries():
    assert verdict(0) == "low"
    assert verdict(24) == "low"
    assert verdict(25) == "medium"
    assert verdict(49) == "medium"
    assert verdict(50) == "high"
    assert verdict(100) == "high"


def test_is_ip_detects_ipv4_and_ipv6_only():
    assert is_ip("192.168.1.1") is True
    assert is_ip("2001:db8::1") is True
    assert is_ip("example.com") is False


def test_benign_https_url_has_no_flags():
    score, flags = score_url("https://example.com")

    assert score == 0
    assert flags == []


def test_readme_example_score_and_flags_are_stable():
    score, flags = score_url("http://secure-login-update-account.top/verify")

    assert score == 33
    assert flags == [
        "multiple_hyphens",
        "suspicious_tld:top",
        "credential_lure_keywords",
    ]


def test_ip_address_host_is_flagged():
    score, flags = score_url("http://192.0.2.10/login")

    assert score == 45
    assert "ip_as_domain" in flags
    assert "many_subdomains" in flags
    assert "credential_lure_keywords" in flags


def test_at_symbol_is_flagged():
    score, flags = score_url("http://example.com@evil.test/login")

    assert score >= 25
    assert "contains_at_symbol" in flags
    assert "credential_lure_keywords" in flags


def test_very_long_url_is_flagged():
    url = "https://example.com/" + "a" * 80

    score, flags = score_url(url)

    assert score == 10
    assert flags == ["very_long_url"]


def test_many_subdomains_are_flagged():
    score, flags = score_url("https://one.two.three.example.com")

    assert score == 10
    assert flags == ["many_subdomains"]


def test_suspicious_tld_is_flagged():
    score, flags = score_url("https://example.xyz")

    assert score == 15
    assert flags == ["suspicious_tld:xyz"]


def test_url_shortener_is_flagged():
    score, flags = score_url("https://bit.ly/example")

    assert score == 10
    assert flags == ["url_shortener"]


def test_score_is_capped_at_100(monkeypatch):
    host = "secure-login-update-password-wallet.a.b.example.top"
    monkeypatch.setattr("detector.SHORTENERS", {host})
    monkeypatch.setattr("detector.is_ip", lambda value: value == host)
    url = f"http://user@{host}/" + "a" * 80

    score, flags = score_url(url)

    assert score == 100
    assert "ip_as_domain" in flags
    assert "url_shortener" in flags


def test_scheme_less_input_is_supported():
    score, flags = score_url("example.com")

    assert score == 0
    assert flags == []


def test_missing_host_is_flagged():
    score, flags = score_url("http://")

    assert score == 20
    assert flags == ["missing_host"]


def test_load_urls_combines_single_url_and_non_comment_file_lines(tmp_path):
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text(
        "\n"
        "# comment\n"
        "https://example.com\n"
        "  https://bit.ly/demo  \n"
        "\n",
        encoding="utf-8",
    )

    assert load_urls(" https://single.test ", urls_file) == [
        "https://single.test",
        "https://example.com",
        "https://bit.ly/demo",
    ]
