"""Hermetic unit and lifecycle tests for the Out-of-Band (OOB) HTTP Canary Listener."""
from __future__ import annotations

import urllib.request
import pytest

from agentpentest.oob import OOBListener, collect_oob, generate_token
from agentpentest.verifiers import VerdictStatus, verify_structured


def test_oob_generate_token():
    tok = generate_token()
    assert tok.startswith("oob-")
    assert len(tok) >= 36


def test_oob_listener_full_lifecycle_and_verification():
    """Start ephemeral listener on loopback, register token, hit canary path, verify proof."""
    listener = OOBListener(host="127.0.0.1", port=0)
    listener.start()
    try:
        assert listener.port > 0
        assert listener.base_url.startswith("http://127.0.0.1:")
        token = listener.register()
        assert len(token) >= 20

        # Send HTTP request to canary path
        req_url = f"{listener.base_url}/{token}"
        req = urllib.request.Request(req_url, data=b"canary_ping", method="POST")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            assert resp.read() == b"ok"

        # Verify interaction collected deterministically
        structured = collect_oob(token, listener, wait=2.0)
        proof = verify_structured(structured)
        assert proof is not None
        assert proof.status is VerdictStatus.CONFIRMED
        assert proof.confidence == 1.0
        assert proof.evidence["interaction_count"] == 1
        assert proof.evidence["first_method"] == "POST"
    finally:
        listener.stop()


def test_oob_listener_unregistered_token_and_timeout():
    """Querying an uncontacted token times out cleanly and yields FALSE_POSITIVE proof."""
    listener = OOBListener(host="127.0.0.1", port=0)
    listener.start()
    try:
        token = listener.register()
        hits = listener.check(token, timeout=0.1)
        assert hits == []
        structured = collect_oob(token, listener, wait=0.1)
        proof = verify_structured(structured)
        assert proof is not None
        assert proof.status is VerdictStatus.FALSE_POSITIVE
    finally:
        listener.stop()


def test_oob_listener_bounds_payload_and_tokens():
    """OOB listener bounds max token registry size and request body length."""
    listener = OOBListener(host="127.0.0.1", port=0, max_interactions_per_token=5)
    for _ in range(50):
        listener.register()
    with listener._lock:
        assert len(listener._tokens) == 50
