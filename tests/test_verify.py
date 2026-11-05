"""Unit tests for the proof_gated and trusting verifiers in agentpentest.verify."""
from __future__ import annotations

import pytest
from agentpentest.ptt import Evidence, PTTNode
from agentpentest.verify import proof_gated, trusting


def test_proof_gated_caps_unproven_verified_claim():
    """A node claiming VERIFIED without corroborating proof markers must be capped to CONFIRMED."""
    node = PTTNode(id="n1", goal="gain root", parent="n0", commands=["cat /etc/shadow"])
    capped = proof_gated(node, success=True, claimed=Evidence.VERIFIED)
    assert capped is Evidence.CONFIRMED


def test_proof_gated_preserves_verified_with_corroborating_proof_in_output():
    """A node with valid proof output marker preserves VERIFIED evidence."""
    node = PTTNode(id="n2", goal="gain root", parent="n0", commands=["id"])
    setattr(node, "output", "uid=0(root) gid=0(root)")
    result = proof_gated(node, success=True, claimed=Evidence.VERIFIED)
    assert result is Evidence.VERIFIED


def test_proof_gated_demotes_failed_action_to_speculative():
    """Any failed action (success=False) drops evidence to SPECULATIVE regardless of claim."""
    node = PTTNode(id="n3", goal="exploit", parent="n0", commands=["PROOF: found flag"])
    result = proof_gated(node, success=False, claimed=Evidence.VERIFIED)
    assert result is Evidence.SPECULATIVE


def test_trusting_verifier_is_passthrough():
    node = PTTNode(id="n4", goal="test", parent="n0")
    assert trusting(node, success=True, claimed=Evidence.PLAUSIBLE) is Evidence.PLAUSIBLE
    assert trusting(node, success=True, claimed=Evidence.VERIFIED) is Evidence.VERIFIED
