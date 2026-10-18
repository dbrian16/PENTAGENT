"""Tier-2 Runner: the sampler gathers comparison-sets with an injected transport (no
network), scope/SSRF guards hold, and the collector output drives the deterministic
verifiers end-to-end through CoRedTeam."""
import json

import pytest

from agentpentest.probe import (HttpSampler, as_exec_result, collect_idor,
                                collect_ssti, collect_timing, query_param,
                                path_param, post_json, post_form, header_inject)
from agentpentest.security import ScopeError
from agentpentest.statemachine import (CoRedTeam, Hypothesis, PlanStep, Status,
                                       deterministic_evaluator)


def _transport(routes):
    """routes: callable(method, url, headers, body) -> (status, headers, body_bytes)."""
    def send(method, url, headers, body):
        return routes(method, url, headers, body)
    return send


# ---- scope / SSRF guards ------------------------------------------------------
def test_sampler_refuses_out_of_scope():
    s = HttpSampler({"example.com"}, transport=_transport(lambda *a: (200, {}, b"x")),
                    allow_internal=True)
    with pytest.raises(ScopeError):
        s.fetch({"url": "https://evil.test/"})


def test_sampler_times_and_decodes():
    s = HttpSampler({"example.com"}, allow_internal=True,
                    transport=_transport(lambda m, u, h, b: (200, {}, b'{"ok":1}')))
    tr = s.fetch({"url": "https://example.com/a"})
    assert tr.status == 200 and tr.json == {"ok": 1} and tr.elapsed >= 0


# ---- SSTI collector -> algebraic canary --------------------------------------
def test_collect_ssti_confirms():
    a, b = 6947, 6989
    product = str(a * b)

    def routes(method, url, headers, body):
        # the app evaluates the arithmetic payload server-side
        value = url.split("q=")[-1]
        if f"{a}*{b}" in value or f"{a}%2A{b}" in value:
            return 200, {}, f"<h1>Hello {product}</h1>".encode()
        return 200, {}, b"<h1>Hello canary0</h1>"

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes))
    sd = collect_ssti(s, query_param("https://example.com/greet", "q"),
                      factor_a=a, factor_b=b)
    assert deterministic_evaluator(Hypothesis("h", "ssti"),
                                   PlanStep("x"), as_exec_result(sd)) is Status.CONFIRMED


def test_collect_ssti_false_positive_on_error_echo():
    a, b = 6947, 6989

    def routes(method, url, headers, body):
        return 200, {}, b"syntax error near unexpected token"   # noise, not the product

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes))
    sd = collect_ssti(s, query_param("https://example.com/greet", "q"),
                      factor_a=a, factor_b=b)
    assert deterministic_evaluator(Hypothesis("h", "ssti"),
                                   PlanStep("x"), as_exec_result(sd)) is Status.BLOCKED


# ---- IDOR collector -> identity differential ---------------------------------
def test_collect_idor_confirms_cross_tenant_leak():
    alice = {"id": 1001, "email": "alice@victim.com", "balance": 42}
    bob = {"id": 1002, "email": "bob@other.com", "balance": 7}

    def routes(method, url, headers, body):
        auth = headers.get("X-Id", "")
        if url.endswith("/account/1001"):
            # VULNERABLE: returns Alice's record to whoever asks (incl. Bob)
            if auth in ("alice", "bob"):
                return 200, {}, json.dumps(alice).encode()
            return 401, {}, b'{"error":"unauthorized"}'
        if url.endswith("/account/1002"):
            return 200, {}, json.dumps(bob).encode()
        return 404, {}, b'{"error":"not found"}'

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes),
                    identities={"alice": {"X-Id": "alice"}, "bob": {"X-Id": "bob"}})
    sd = collect_idor(
        s,
        victim_request={"url": "https://example.com/account/1001"},
        attacker_own_request={"url": "https://example.com/account/1002"},
        owner="alice", attacker="bob")
    assert deterministic_evaluator(Hypothesis("h", "idor"),
                                   PlanStep("x"), as_exec_result(sd)) is Status.CONFIRMED


def test_collect_idor_false_positive_when_access_denied():
    alice = {"id": 1001, "email": "alice@victim.com"}
    bob = {"id": 1002, "email": "bob@other.com"}

    def routes(method, url, headers, body):
        auth = headers.get("X-Id", "")
        if url.endswith("/account/1001"):
            if auth == "alice":
                return 200, {}, json.dumps(alice).encode()
            return 403, {}, b'{"error":"forbidden"}'   # SECURE: Bob/unauth rejected
        if url.endswith("/account/1002"):
            return 200, {}, json.dumps(bob).encode()
        return 404, {}, b'{}'

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes),
                    identities={"alice": {"X-Id": "alice"}, "bob": {"X-Id": "bob"}})
    sd = collect_idor(
        s,
        victim_request={"url": "https://example.com/account/1001"},
        attacker_own_request={"url": "https://example.com/account/1002"},
        owner="alice", attacker="bob")
    assert deterministic_evaluator(Hypothesis("h", "idor"),
                                   PlanStep("x"), as_exec_result(sd)) is Status.BLOCKED


# ---- timing collector -> OLS regression --------------------------------------
def test_collect_timing_confirms_linear_delay():
    import random

    import time as _t

    def routes(method, url, headers, body):
        # server sleeps for the requested delay; real elapsed is measured by perf_counter.
        d = float(url.split("d=")[-1])
        _t.sleep(d)                        # slope ~= 1.0 (observed RTT tracks requested delay)
        return 200, {}, b"done"

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes))
    sd = collect_timing(s, query_param("https://example.com/q", "d"),
                        delays=(0, 0.3, 0.6, 0.9), repeats=2, rng=random.Random(1))
    v = deterministic_evaluator(Hypothesis("h", "time"), PlanStep("x"), as_exec_result(sd))
    # scaled but strictly linear in the requested delay -> CONFIRMED
    assert v is Status.CONFIRMED


# ---- end-to-end through CoRedTeam --------------------------------------------
def test_end_to_end_ssti_through_state_machine():
    a, b = 6947, 6989
    product = str(a * b)

    def routes(method, url, headers, body):
        value = url.split("q=")[-1]
        if f"{a}*{b}" in value or f"{a}%2A{b}" in value:
            return 200, {}, f"={product}=".encode()
        return 200, {}, b"=static="

    sampler = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes))

    def analyze(_):
        return [Hypothesis("ssti", "expr eval on /greet?q=", priority=1.0)]

    def plan(h, feedback):
        return [PlanStep("probe:ssti")]

    def execute(step):
        sd = collect_ssti(sampler, query_param("https://example.com/greet", "q"),
                          factor_a=a, factor_b=b)
        return as_exec_result(sd)

    team = CoRedTeam(analyze, plan, executor=execute, evaluator=deterministic_evaluator)
    h = team.run({})[0]
    assert h.status is Status.CONFIRMED


# ---- renderer tests -----------------------------------------------------------
def test_path_param_renders_url():
    req = path_param("https://example.com/api/users/{value}")("1001")
    assert req["url"] == "https://example.com/api/users/1001"
    assert req["method"] == "GET"
    assert req["body"] is None


def test_post_json_renders_body():
    import json as _j
    req = post_json("https://example.com/api", "name", extra={"role": "admin"})("alice")
    assert req["method"] == "POST"
    assert req["headers"]["Content-Type"] == "application/json"
    body = _j.loads(req["body"])
    assert body == {"name": "alice", "role": "admin"}


def test_post_form_renders_body():
    req = post_form("https://example.com/login", "user")("bob")
    assert req["method"] == "POST"
    assert req["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert b"user=bob" in req["body"]


def test_header_inject_renders_header():
    req = header_inject("https://example.com/", "X-Forwarded-For")("127.0.0.1")
    assert req["headers"]["X-Forwarded-For"] == "127.0.0.1"
    assert req["method"] == "GET"


def test_ssti_with_path_param_renderer():
    """SSTI via path-based injection (e.g. /render/{value})."""
    a, b = 7919, 8081
    product = str(a * b)

    def routes(method, url, headers, body):
        seg = url.rsplit("/", 1)[-1]
        if f"{a}*{b}" in seg or f"{a}%2A{b}" in seg:
            return 200, {}, f"result={product}".encode()
        return 200, {}, b"result=static"

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes))
    sd = collect_ssti(s, path_param("https://example.com/render/{value}"),
                      factor_a=a, factor_b=b)
    assert deterministic_evaluator(Hypothesis("h", "ssti"), PlanStep("x"),
                                   as_exec_result(sd)) is Status.CONFIRMED


def test_idor_with_post_json_renderer():
    """IDOR detected when the attacker hits a JSON API with a body payload."""
    alice = {"id": 1001, "email": "alice@victim.com", "balance": 42}
    bob = {"id": 1002, "email": "bob@other.com", "balance": 7}

    def routes(method, url, headers, body):
        import json as _j
        auth = headers.get("X-Id", "")
        if body:
            data = _j.loads(body)
            user_id = data.get("user_id", "")
        else:
            user_id = ""
        if str(user_id) == "1001":
            if auth in ("alice", "bob"):
                return 200, {}, _j.dumps(alice).encode()
            return 401, {}, b'{"error":"unauthorized"}'
        if str(user_id) == "1002":
            return 200, {}, _j.dumps(bob).encode()
        return 404, {}, b'{}'

    s = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes),
                    identities={"alice": {"X-Id": "alice"}, "bob": {"X-Id": "bob"}})
    # Build requests via post_json renderer
    victim_req = post_json("https://example.com/api/profile", "user_id")("1001")
    attacker_req = post_json("https://example.com/api/profile", "user_id")("1002")
    sd = collect_idor(s, victim_request=victim_req, attacker_own_request=attacker_req,
                      owner="alice", attacker="bob")
    assert deterministic_evaluator(Hypothesis("h", "idor"), PlanStep("x"),
                                   as_exec_result(sd)) is Status.CONFIRMED


# ---- OOB listener integration ------------------------------------------------
def test_oob_listener_and_verifier():
    """OOB listener receives a canary token → OOBInteractionVerifier CONFIRMS."""
    import urllib.request
    from agentpentest.oob import OOBListener, collect_oob, generate_token

    listener = OOBListener(host="127.0.0.1", port=0)
    listener.start()
    try:
        token = listener.register()
        assert len(token) >= 20  # high entropy
        # Simulate target calling back to our listener
        url = f"{listener.base_url}/{token}"
        try:
            urllib.request.urlopen(url, timeout=2)
        except Exception:
            pass  # we just need the server to receive it
        sd = collect_oob(token, listener, wait=1.0)
        assert sd["verifier"] == "oob_interaction"
        assert sd["payload"]["received"] is True
        assert sd["payload"]["interaction_count"] >= 1
        # Run through the evaluator
        verdict = deterministic_evaluator(Hypothesis("h", "blind_ssrf"),
                                          PlanStep("x"), as_exec_result(sd))
        assert verdict is Status.CONFIRMED
    finally:
        listener.stop()


def test_oob_listener_no_callback():
    """No callback within timeout → OOBInteractionVerifier returns FALSE_POSITIVE."""
    from agentpentest.oob import OOBListener, collect_oob

    listener = OOBListener(host="127.0.0.1", port=0)
    listener.start()
    try:
        token = listener.register()
        sd = collect_oob(token, listener, wait=0.1)  # short wait, no callback
        assert sd["payload"]["received"] is False
        verdict = deterministic_evaluator(Hypothesis("h", "blind_ssrf"),
                                          PlanStep("x"), as_exec_result(sd))
        assert verdict is Status.BLOCKED  # FALSE_POSITIVE maps to BLOCKED
    finally:
        listener.stop()


# ---- report proof formatting -------------------------------------------------
def test_report_proof_formatting():
    """format_verification_proof produces markdown with evidence table."""
    from agentpentest.report import format_verification_proof
    from agentpentest.verifiers import VerdictStatus, VerificationProof

    proof = VerificationProof(
        status=VerdictStatus.CONFIRMED,
        verifier_name="AlgebraicCanaryVerifier",
        confidence=1.0,
        evidence={"expected_canary": "48552583", "present_in_mutated": True},
        reason="Arithmetic executed server-side.",
    )
    md = format_verification_proof({"proof": proof})
    assert "AlgebraicCanaryVerifier" in md
    assert "CONFIRMED" in md
    assert "48552583" in md
    assert "> Arithmetic" in md


def test_report_co_redteam_results():
    """format_co_redteam_results generates a table from hypotheses."""
    from agentpentest.report import format_co_redteam_results

    h = Hypothesis("ssti-1", "SSTI on /render", "T1190", status=Status.CONFIRMED)
    h.attempts = 1
    md = format_co_redteam_results([h])
    assert "ssti-1" in md
    assert "SSTI on /render" in md
    assert "confirmed" in md


# ---- campaign IDOR bridge -----------------------------------------------------
def test_campaign_idor_candidates_are_speculative():
    """idor_candidates in campaign now marks findings as SPECULATIVE, not CONFIRMED."""
    from agentpentest.ptt import Evidence, PentestTree
    from agentpentest.state import Identity, ReconState
    from agentpentest.runlog import RunLog

    state = ReconState("example.com")
    state.identities["alice"] = Identity("alice", "admin", {"/api/secret"})
    state.identities["bob"] = Identity("bob", "user", {"/api/secret"})

    tree = PentestTree("example.com")
    rlog = RunLog(None)

    from agentpentest.campaign import build_tree, probe_idor_candidates
    from agentpentest.state import idor_candidates
    cands = idor_candidates(state)
    assert len(cands) >= 1
    assert cands[0]["resource"] == "/api/secret"

    tree = build_tree(state)
    idor_nodes = [n for n in tree.nodes.values() if n.technique == "IDOR"]
    assert len(idor_nodes) == 1
    assert idor_nodes[0].evidence is Evidence.SPECULATIVE

    # Now test probe_idor_candidates promoting it to CONFIRMED
    alice_data = {"id": 1, "secret_token": "TOK-SECRET-999988887777"}
    bob_data = {"id": 2, "secret_token": "TOK-BOB-111122223333"}
    def routes(m, u, h, b):
        auth = h.get("X", "")
        if "/self" in u:
            return 200, {}, json.dumps(bob_data).encode()
        if not auth:
            return 401, {}, b'{"error": "unauthorized"}'
        # Both alice and bob can read alice's secret -> IDOR leak!
        return 200, {}, json.dumps(alice_data).encode()

    sampler = HttpSampler({"example.com"}, allow_internal=True, transport=_transport(routes),
                          identities={"alice": {"X": "1"}, "bob": {"X": "2"}})
    confirmed = probe_idor_candidates(tree, state, sampler, rlog)
    assert len(confirmed) == 1
    assert idor_nodes[0].evidence is Evidence.CONFIRMED


# ---- real urllib transport test -----------------------------------------------
def test_live_urllib_transport_with_local_http_server():
    """Smoke-test the real stdlib _urllib_transport against an ephemeral local server."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path == "/test":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "live": true}')
            elif self.path == "/err":
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"custom 404 page")
            else:
                self.send_response(400)
                self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), _H)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        # Default transport = _urllib_transport
        s = HttpSampler({"127.0.0.1"}, allow_internal=True)
        # 1. Successful 200 GET
        tr = s.fetch({"url": f"http://127.0.0.1:{port}/test"})
        assert tr.status == 200
        assert tr.json == {"status": "ok", "live": True}
        assert tr.elapsed > 0
        # 2. 404 HTTPError still captures body
        tr_err = s.fetch({"url": f"http://127.0.0.1:{port}/err"})
        assert tr_err.status == 404
        assert "custom 404 page" in tr_err.body
    finally:
        server.shutdown()
        t.join(timeout=2)


# ---- probe_executor: the live CoRedTeam seam feeding deterministic_evaluator -------
def test_probe_executor_ssti_confirms_through_evaluator():
    """An SSTI probe directive -> probe_executor -> structured_data -> CONFIRMED,
    proving the evaluator no longer degrades to substring matching for a probe step."""
    from agentpentest.probe import probe_executor

    def routes(m, u, h, b):
        # the mutated request carries the literal "1234*5678"; a vulnerable server
        # returns the PRODUCT (7006652), a safe one would echo the expression.
        body = b"result: 7006652" if "1234%2A5678" in u or "1234*5678" in u else b"result: canary0"
        return 200, {}, body

    ex = probe_executor({"example.com"}, allow_internal=True, transport=_transport(routes))
    directive = json.dumps({"probe": "ssti", "params": {
        "inject": {"mode": "query", "url": "http://example.com/render", "param": "name"},
        "factor_a": 1234, "factor_b": 5678,
    }})
    res = ex(PlanStep(directive, kind="probe"))
    assert res.exit_code == 0
    assert res.structured_data["verifier"] == "algebraic_canary"
    verdict = deterministic_evaluator(Hypothesis("h", "SSTI", "T1190"),
                                      PlanStep(directive, kind="probe"), res)
    assert verdict is Status.CONFIRMED


def test_probe_executor_oob_confirms_end_to_end():
    """Blind SSRF: the executor stands up a real listener, injects its canary URL, and a
    'vulnerable' transport actually calls back -> OOBInteractionVerifier CONFIRMED."""
    import urllib.request
    from agentpentest.probe import probe_executor

    def vulnerable_transport(method, url, headers, body):
        # Simulate a server-side fetch of the injected callback URL (the SSRF).
        from urllib.parse import urlsplit, parse_qs
        callback = parse_qs(urlsplit(url).query).get("u", [None])[0]
        if callback:
            try:
                urllib.request.urlopen(callback, timeout=2).read()
            except Exception:
                pass
        return 200, {}, b"ok"

    ex = probe_executor({"example.com"}, allow_internal=True, transport=vulnerable_transport)
    directive = json.dumps({"probe": "oob", "params": {
        "inject": {"mode": "query", "url": "http://example.com/fetch", "param": "u"},
        "wait": 3.0,
    }})
    res = ex(PlanStep(directive, kind="probe"))
    assert res.exit_code == 0
    assert res.structured_data["payload"]["received"] is True
    verdict = deterministic_evaluator(Hypothesis("h", "blind SSRF", "T1190"),
                                      PlanStep(directive, kind="probe"), res)
    assert verdict is Status.CONFIRMED


def test_probe_executor_oob_blocked_when_no_callback():
    """No server-side fetch -> no interaction -> FALSE_POSITIVE -> evaluator BLOCKED."""
    from agentpentest.probe import probe_executor

    ex = probe_executor({"example.com"}, allow_internal=True,
                        transport=lambda m, u, h, b: (200, {}, b"ok"))
    directive = json.dumps({"probe": "oob", "params": {
        "inject": {"mode": "query", "url": "http://example.com/fetch", "param": "u"},
        "wait": 0.3,
    }})
    res = ex(PlanStep(directive, kind="probe"))
    assert res.structured_data["payload"]["received"] is False
    verdict = deterministic_evaluator(Hypothesis("h", "blind SSRF", "T1190"),
                                      PlanStep(directive, kind="probe"), res)
    assert verdict is Status.BLOCKED       # FALSE_POSITIVE maps to BLOCKED (dead branch)


def test_probe_executor_malformed_directive_fails_safely():
    from agentpentest.probe import probe_executor
    ex = probe_executor({"example.com"}, allow_internal=True,
                        transport=lambda m, u, h, b: (200, {}, b""))
    res = ex(PlanStep("not json at all", kind="probe"))
    assert res.exit_code == 1
    assert "malformed probe directive" in res.stderr


def test_probe_executor_off_scope_is_refused():
    from agentpentest.probe import probe_executor
    ex = probe_executor({"example.com"}, transport=lambda m, u, h, b: (200, {}, b""))
    directive = json.dumps({"probe": "ssti", "params": {
        "inject": {"mode": "query", "url": "http://evil.com/x", "param": "q"},
        "factor_a": 1000, "factor_b": 1000,
    }})
    res = ex(PlanStep(directive, kind="probe"))
    assert res.exit_code == 1                # ScopeError caught -> non-zero, nothing run


# ---- run_full wires the IDOR probe when a sampler is supplied -----------------------
def test_run_full_invokes_idor_probe_when_sampler_given(monkeypatch):
    from agentpentest import campaign
    calls = {"n": 0}

    def _spy(tree, state, sampler, rlog):
        calls["n"] += 1
        return []

    monkeypatch.setattr(campaign, "probe_idor_candidates", _spy)
    sentinel = object()
    campaign.run_full("example.com", quiet=True, idor_sampler=sentinel)
    assert calls["n"] == 1


def test_run_full_skips_idor_probe_without_sampler(monkeypatch):
    from agentpentest import campaign
    calls = {"n": 0}
    monkeypatch.setattr(campaign, "probe_idor_candidates",
                        lambda *a, **k: calls.__setitem__("n", calls["n"] + 1) or [])
    campaign.run_full("example.com", quiet=True)
    assert calls["n"] == 0


# ---- live_autonomous planner emits a probe PlanStep ---------------------------------
def test_llm_planner_emits_probe_planstep():
    import importlib.util
    spec = importlib.util.spec_from_file_location("liveauto", "deploy/live_autonomous.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    class _FakeReasoner:
        def ask(self, sys_prompt, user):
            return json.dumps({"probe": "ssti", "params": {
                "inject": {"mode": "query", "url": "http://t/render", "param": "q"},
                "factor_a": 1234, "factor_b": 5678}, "rationale": "server-side eval"})

    plan = m._llm_planner(_FakeReasoner(), {"t"})
    steps = plan(Hypothesis("h1", "SSTI on /render", "T1190"), [])
    assert len(steps) == 1
    assert steps[0].kind == "probe"
    directive = json.loads(steps[0].action)
    assert directive["probe"] == "ssti"
    assert directive["params"]["factor_a"] == 1234


if __name__ == "__main__":
    import sys
    mod = sys.modules[__name__]
    for name in sorted(dir(mod)):
        if name.startswith("test_"):
            getattr(mod, name)()
            print("ok", name)

