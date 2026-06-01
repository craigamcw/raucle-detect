"""Security regression tests for raucle_detect.feed.

Covers:
  * FEED-SSRF: fetch_feed must reject non-https schemes, private/loopback/
    link-local hosts (incl. cloud metadata IP), redirects, and oversized bodies.
  * KEY-PERMS: private keys must be written 0600.
"""

from __future__ import annotations

import os
import stat

import pytest

from raucle_detect import feed
from raucle_detect.feed import IOCSigner, fetch_feed

# ---------------------------------------------------------------------------
# FEED-SSRF
# ---------------------------------------------------------------------------


def test_fetch_feed_rejects_file_scheme():
    with pytest.raises(ValueError, match="only https"):
        fetch_feed("file:///etc/passwd")


def test_fetch_feed_rejects_http_scheme():
    with pytest.raises(ValueError, match="only https"):
        fetch_feed("http://example.com/feed.json")


def test_fetch_feed_rejects_ftp_scheme():
    with pytest.raises(ValueError, match="only https"):
        fetch_feed("ftp://example.com/feed.json")


def test_fetch_feed_rejects_loopback_host():
    # https scheme but resolves to loopback -> blocked before any network read.
    with pytest.raises(ValueError, match="disallowed|private|loopback|link-local"):
        fetch_feed("https://localhost/feed.json")


def test_fetch_feed_rejects_private_ip_host():
    with pytest.raises(ValueError, match="disallowed|private"):
        fetch_feed("https://127.0.0.1/feed.json")
    with pytest.raises(ValueError, match="disallowed|private"):
        fetch_feed("https://10.0.0.1/feed.json")


def test_fetch_feed_rejects_metadata_ip():
    with pytest.raises(ValueError, match="disallowed|metadata|link-local"):
        fetch_feed("https://169.254.169.254/latest/meta-data/")


def test_is_blocked_ip_classifications():
    assert feed._is_blocked_ip("127.0.0.1")
    assert feed._is_blocked_ip("169.254.169.254")
    assert feed._is_blocked_ip("10.1.2.3")
    assert feed._is_blocked_ip("192.168.1.1")
    assert feed._is_blocked_ip("::1")
    assert feed._is_blocked_ip("not-an-ip")  # fail closed
    assert not feed._is_blocked_ip("8.8.8.8")
    assert not feed._is_blocked_ip("1.1.1.1")


class _FakeResp:
    """Stands in for http.client.HTTPResponse."""

    def __init__(self, status, body=b""):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body


def _fake_conn_base(resp):
    """A fake http.client.HTTPSConnection base whose request/getresponse are no-ops.

    fetch_feed defines `_PinnedHTTPSConnection(http.client.HTTPSConnection)` at call
    time, so patching the base here makes the pinned subclass inherit these fakes —
    and the real `connect()`/socket are never touched.
    """
    import http.client

    class _Fake:
        def __init__(self, *a, **k):
            pass

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return resp

        def close(self):
            pass

    return http.client, _Fake


def test_fetch_feed_caps_body_size(monkeypatch):
    """An oversized response body is rejected even from an allowed host."""
    oversize = b"x" * (feed._MAX_FEED_BYTES + 100)
    monkeypatch.setattr(feed, "_assert_safe_url", lambda url: ("example.com", "93.184.216.34"))
    http_client, fake = _fake_conn_base(_FakeResp(200, oversize))
    monkeypatch.setattr(http_client, "HTTPSConnection", fake)

    with pytest.raises(ValueError, match="exceeds"):
        fetch_feed("https://example.com/feed.json")


def test_fetch_feed_rejects_redirects(monkeypatch):
    """A redirect response must raise rather than being followed."""
    monkeypatch.setattr(feed, "_assert_safe_url", lambda url: ("example.com", "93.184.216.34"))
    http_client, fake = _fake_conn_base(_FakeResp(302))
    monkeypatch.setattr(http_client, "HTTPSConnection", fake)

    with pytest.raises(ValueError, match="redirect"):
        fetch_feed("https://example.com/feed.json")


# ---------------------------------------------------------------------------
# KEY-PERMS
# ---------------------------------------------------------------------------


def test_save_private_key_is_0600(tmp_path):
    signer = IOCSigner.generate(issuer="test.local")
    path = tmp_path / "issuer.pem"
    signer.save_private_key(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_save_private_key_tightens_existing_loose_file(tmp_path):
    path = tmp_path / "issuer.pem"
    path.write_text("placeholder")
    os.chmod(path, 0o644)
    signer = IOCSigner.generate(issuer="test.local")
    signer.save_private_key(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600 after rewrite, got {oct(mode)}"


def test_write_private_bytes_helper_is_0600(tmp_path):
    path = tmp_path / "raw.key"
    feed._write_private_bytes(path, b"secret-bytes")
    assert path.read_bytes() == b"secret-bytes"
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
